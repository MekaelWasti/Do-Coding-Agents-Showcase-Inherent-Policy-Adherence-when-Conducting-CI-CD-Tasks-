"""Cache immutable commit parents in read-only GraphQL batches.

Only exact OID matches with complete parent connections are accepted. Recovery
can consume these records instead of fetching each current PR's commit list.
Missing/partial objects retain the existing authenticated REST fallback.
"""
import collections
import hashlib
import json
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import pyarrow.parquet as pq
from stream_aidev import OUT, save_json

PARENTS = OUT / 'commit_parents'
QUERIES = OUT / 'github_graphql_cache'
RATE_LOCK = threading.Lock()
RATE_UNTIL = 0
DOC = 'https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api'


def parent_path(repo, sha):
    return PARENTS / (hashlib.sha256((repo + ':' + sha).encode()).hexdigest() + '.json')


def query_for(items):
    grouped = collections.defaultdict(list)
    for repo, sha in items:
        grouped[repo].append(sha)
    fields = []
    aliases = {}
    for index, (repo, shas) in enumerate(grouped.items()):
        owner, name = repo.split('/', 1)
        objects = []
        for number, sha in enumerate(shas):
            alias = 'c' + str(number)
            objects.append(alias + ': object(oid: ' + json.dumps(sha) + ') { ... on Commit { oid parents(first: 100) { nodes { oid } pageInfo { hasNextPage } } } }')
            aliases[('r' + str(index), alias)] = (repo, sha)
        fields.append('r' + str(index) + ': repository(owner: ' + json.dumps(owner) + ', name: ' + json.dumps(name) + ') { ' + ' '.join(objects) + ' }')
    return 'query { ' + ' '.join(fields) + ' rateLimit { cost remaining resetAt } }', aliases


def complete_parents(node, sha):
    if not isinstance(node, dict) or node.get('oid') != sha:
        return None
    connection = node.get('parents') or {}
    if connection.get('pageInfo', {}).get('hasNextPage') is not False:
        return None
    nodes = connection.get('nodes')
    if not isinstance(nodes, list) or any(not isinstance(n, dict) or not n.get('oid') for n in nodes):
        return None
    return [dict(sha=n['oid']) for n in nodes]


def fetch(items):
    global RATE_UNTIL
    query, aliases = query_for(items)
    digest = hashlib.sha256(query.encode()).hexdigest()
    path = QUERIES / (digest + '.json')
    record = None
    if path.exists():
        try:
            cached = json.loads(path.read_text(encoding='utf-8'))
            if cached.get('status') in ['ok', 'partial_not_found']:
                record = cached
        except (OSError, ValueError):
            pass
    for attempt in range(5):
        if record is not None:
            break
        while time.time() < RATE_UNTIL:
            time.sleep(max(.1, min(10, RATE_UNTIL - time.time())))
        try:
            run = subprocess.run(['gh', 'api', 'graphql', '--input', '-'],
                                 input=json.dumps({'query': query}), capture_output=True,
                                 text=True, encoding='utf-8', errors='replace', timeout=120)
            response = json.loads(run.stdout) if run.stdout else {}
            message = run.stderr
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            response = {}; message = str(exc)
        errors = response.get('errors') or []
        stable_missing = errors and all(e.get('type') == 'NOT_FOUND' for e in errors)
        status = 'ok' if not errors and response.get('data') else 'partial_not_found' if stable_missing else 'error'
        candidate = dict(query=query, query_sha256=digest, response=response, status=status, error=message)
        save_json(path, candidate)
        rate = (response.get('data') or {}).get('rateLimit') or {}
        if rate.get('remaining') == 0 or 'rate limit' in (message + json.dumps(errors)).lower():
            with RATE_LOCK:
                try:
                    reset = datetime.fromisoformat(rate['resetAt'].replace('Z', '+00:00')).timestamp() + 2
                except (KeyError, ValueError):
                    reset = time.time() + 60 * (2 ** attempt)
                RATE_UNTIL = max(RATE_UNTIL, reset)
            print('GraphQL rate-limited; waiting for reset', flush=True)
        if status in ['ok', 'partial_not_found']:
            record = candidate
            break
        if attempt < 4:
            time.sleep(min(60, 2 ** attempt))
    record = record or candidate
    data = record['response'].get('data') or {}
    saved = 0
    for (repository_alias, commit_alias), (repo, sha) in aliases.items():
        node = (data.get(repository_alias) or {}).get(commit_alias)
        parents = complete_parents(node, sha)
        if parents is not None:
            save_json(parent_path(repo, sha), dict(repo=repo, sha=sha, parents=parents,
                      source='GitHub_GraphQL_Commit_parents', query_sha256=digest, complete=True))
            saved += 1
    return dict(requested=len(items), saved=saved, status=record['status'],
                cost=(data.get('rateLimit') or {}).get('cost'))


def main():
    PARENTS.mkdir(parents=True, exist_ok=True)
    QUERIES.mkdir(parents=True, exist_ok=True)
    repos = {r['id']: r['repo'] for r in pq.read_table(OUT / 'workflow_prs.parquet', columns=['id', 'repo']).to_pylist()}
    recovered = set()
    for path in (OUT / 'recovered_prs').glob('*.json'):
        try:
            record = json.loads(path.read_text(encoding='utf-8'))
            if record['status'] == 'recovered' and record.get('recovery_revision') == 2:
                recovered.add(record['pr_id'])
        except (OSError, ValueError):
            pass
    wanted = set()
    for batch in pq.ParquetFile(OUT / 'workflow_pr_commits.parquet').iter_batches(batch_size=8192):
        for row in batch.to_pylist():
            key = (repos[row['pr_id']], row['sha'])
            if row['pr_id'] not in recovered and not parent_path(*key).exists():
                wanted.add(key)
    ordered = sorted(wanted)
    batches = [ordered[i:i + 100] for i in range(0, len(ordered), 100)]
    totals = collections.Counter()
    with ThreadPoolExecutor(max_workers=2) as pool:
        # Bound scheduled responses too; do not enqueue the whole network stage.
        for offset in range(0, len(batches), 2):
            for result in pool.map(fetch, batches[offset:offset + 2]):
                totals.update({k: result[k] for k in ['requested', 'saved']})
                totals['batches'] += 1
                totals['cost'] += result['cost'] or 0
                totals['unresolved'] += result['requested'] - result['saved']
                if totals['batches'] % 10 == 0:
                    save_json(OUT / 'parent_prefetch_progress.json', dict(totals, target_commits=len(ordered)))
                    print(f"Parent metadata {totals['requested']}/{len(ordered)}; saved {totals['saved']}", flush=True)
    save_json(OUT / 'parent_prefetch_counts.json', dict(totals, target_commits=len(ordered), documentation=DOC))
    print(json.dumps(dict(totals), indent=2))


if __name__ == '__main__':
    main()
