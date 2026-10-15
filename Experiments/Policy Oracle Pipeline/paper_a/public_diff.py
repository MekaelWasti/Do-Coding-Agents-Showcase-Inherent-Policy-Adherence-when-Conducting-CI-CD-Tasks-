"""Read immutable GitHub comparison diffs; reject uncertain path metadata."""
import codecs
import hashlib
import json
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from stream_aidev import OUT, save_json

CACHE = OUT / 'public_diff_cache'
RATE_LOCK = threading.Lock()
RATE_UNTIL = 0


def git_path(value):
    if value.startswith('"'):
        if not value.endswith('"'):
            raise ValueError('Unterminated quoted Git path')
        value = codecs.escape_decode(value[1:-1].encode('utf-8'))[0].decode('utf-8')
    return value


def parse_diff(text):
    if not text.startswith('diff --git '):
        raise ValueError('Response is not a Git diff')
    files = []
    for chunk in re.split(r'(?m)^diff --git ', text)[1:]:
        lines = chunk.splitlines()
        headers = []
        for line in lines[1:]:
            if line.startswith('@@') or line == 'GIT binary patch':
                break
            headers.append(line)
        info = {}
        for line in headers:
            for prefix, key in [('rename from ', 'old'), ('rename to ', 'new'),
                                ('copy from ', 'copy_old'), ('copy to ', 'copy_new')]:
                if line.startswith(prefix):
                    info[key] = git_path(line[len(prefix):])
            for prefix, key, lead in [('--- ', 'before', 'a/'), ('+++ ', 'after', 'b/')]:
                if line.startswith(prefix):
                    # Unified diff paths end at the tab timestamp separator.
                    # Literal tabs inside Git paths are quoted/escaped.
                    path = git_path(line[len(prefix):].split('\t', 1)[0])
                    if path == '/dev/null':
                        info[key] = None
                    elif path.startswith(lead):
                        info[key] = path[2:]
                    else:
                        raise ValueError('Unexpected diff path prefix')
        # Pure mode changes/binary files have no ---/+++ lines.
        if not any(key in info for key in ['new', 'copy_new', 'after', 'before']):
            header = lines[0]
            if header.startswith('"'):
                match = re.fullmatch(r'("(?:[^"\\]|\\.)*") ("(?:[^"\\]|\\.)*")', header)
                if not match:
                    raise ValueError('Ambiguous quoted diff header')
                old, new = map(git_path, match.groups())
            else:
                match = re.fullmatch(r'(a/\S+) (b/\S+)', header)
                if not match:
                    raise ValueError('Ambiguous diff header')
                old, new = match.groups()
            info.update(before=old[2:], after=new[2:])
        filename = info.get('new') or info.get('copy_new') or info.get('after') or info.get('before')
        if not filename:
            raise ValueError('Diff file has no recoverable path')
        status = ('renamed' if info.get('new') else 'added' if info.get('copy_new')
                  or any(line.startswith('new file mode ') for line in headers)
                  else 'removed' if any(line.startswith('deleted file mode ') for line in headers)
                  else 'modified')
        row = dict(filename=filename, status=status)
        if status == 'renamed':
            if not info.get('old'):
                raise ValueError('Rename has no previous filename')
            row['previous_filename'] = info['old']
        start = next((i for i, line in enumerate(lines) if line.startswith('@@')), None)
        row['patch'] = '\n'.join(lines[start:]) + '\n' if start is not None else None
        files.append(row)
    if len(files) != len({r['filename'] for r in files}):
        raise ValueError('Duplicate paths in comparison diff')
    return files


def workflow_sections(body):
    """Select CI diff sections before decoding unrelated repository content."""
    selected=[]
    for chunk in re.split(rb'(?m)^diff --git ',body)[1:]:
        headers=chunk.split(b'\n@@',1)[0].split(b'\nGIT binary patch',1)[0]
        first=headers.split(b'\n',1)[0]
        relevant=(first.startswith((b'a/.github/workflows/',b'"a/.github/workflows/'))
            or b' b/.github/workflows/' in first or b' "b/.github/workflows/' in first
            or any(line.startswith((b'rename from .github/workflows/',b'rename to .github/workflows/',
                                    b'copy from .github/workflows/',b'copy to .github/workflows/'))
                   for line in headers.splitlines()))
        if relevant:selected.append(b'diff --git '+chunk)
    return b''.join(selected).decode('utf-8')


def read_workflow_diff(response):
    digest=hashlib.sha256(); total=0; selected=bytearray(); keeping=False
    for index,line in enumerate(response):
        if index==0 and not line.startswith(b'diff --git '):
            raise ValueError('Response is not a Git diff')
        digest.update(line); total+=len(line)
        if line.startswith(b'diff --git '):
            header=line[len(b'diff --git '):]
            keeping=(header.startswith((b'a/.github/workflows/',b'"a/.github/workflows/'))
                or b' b/.github/workflows/' in header or b' "b/.github/workflows/' in header)
        if keeping:selected.extend(line)
    expected=response.headers.get('Content-Length')
    if total==0 or (expected and total!=int(expected)):
        raise ValueError('Empty or incomplete comparison diff')
    return selected.decode('utf-8'),digest.hexdigest(),total


def fetch(repo, base, head):
    global RATE_UNTIL
    CACHE.mkdir(parents=True, exist_ok=True)
    url = f'https://github.com/{repo}/compare/{base}...{head}.diff'
    path = CACHE / (hashlib.sha256(url.encode()).hexdigest() + '.json')
    if path.exists():
        try:
            cached = json.loads(path.read_text(encoding='utf-8'))
            if cached['status'] == 'ok':
                if cached.get('parser_revision', 0) < 4:
                    cached['files'] = parse_diff(cached['text']) if cached['text'] else []
                    cached['parser_revision'] = 4
                    save_json(path, cached)
                return cached
        except (OSError, ValueError):
            pass
    result = dict(url=url, status='error', error='No response')
    for attempt in range(3):
        while time.time() < RATE_UNTIL:
            time.sleep(max(.1, min(10, RATE_UNTIL - time.time())))
        try:
            with urlopen(Request(url, headers={'User-Agent': 'paper-a-research'}), timeout=60) as response:
                text,digest,total=read_workflow_diff(response)
            files = parse_diff(text) if text else []
            result = dict(url=url, status='ok', text=text, files=files,
                          sha256=digest, source='GitHub_public_comparison_diff',
                          workflow_only=True,full_response_bytes=total,parser_revision=4)
            break
        except HTTPError as exc:
            result = dict(url=url, status='error', error=str(exc), http_status=exc.code)
            if exc.code in [403, 429]:
                with RATE_LOCK:
                    try:
                        delay = max(60, float(exc.headers.get('Retry-After', 60)))
                    except ValueError:
                        delay = 60
                    RATE_UNTIL = max(RATE_UNTIL, time.time() + delay)
                # Honor the public endpoint's backoff before using the REST fallback.
                while time.time() < RATE_UNTIL:
                    time.sleep(max(.1, min(10, RATE_UNTIL - time.time())))
            if exc.code < 500:
                break
        except (URLError, ValueError, UnicodeError, TimeoutError) as exc:
            result = dict(url=url, status='error', error=str(exc))
        if attempt < 2:
            time.sleep(2 ** attempt)
    save_json(path, result)
    return result
