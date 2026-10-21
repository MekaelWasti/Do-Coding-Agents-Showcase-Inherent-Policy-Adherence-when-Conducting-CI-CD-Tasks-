"""Verify the frozen generated-output copy before switching storage paths."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'outputs'
TARGET = Path(r'E:\!My Files\CS\Grammar\WorkflowResearch_Generated\paper_a_outputs')


def inventory(root):
    result = {}
    for directory, _, names in os.walk(root):
        for name in names:
            path = Path(directory) / name
            result[str(path.relative_to(root))] = path.stat().st_size
    return result


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def main():
    source = inventory(SOURCE)
    target = inventory(TARGET)
    errors = []
    if source != target:
        errors.append('Relative file names or sizes differ')
    # Hash every published parquet plus the root-level provenance/config files.
    # Cached response transfers are covered by Robocopy's full copy report and
    # the complete name/size inventory; do not claim they were all rehashed.
    checked = []
    for relative in source:
        path = Path(relative)
        critical = (path.suffix == '.parquet' and '.partial.' not in path.name
                    or len(path.parts) == 1 and path.suffix in {'.json', '.csv', '.md'})
        if not critical or relative not in target:
            continue
        left = digest(SOURCE / relative)
        right = digest(TARGET / relative)
        checked.append(dict(path=relative, sha256=left, matches=left == right))
        if left != right:
            errors.append('Hash differs: ' + relative)
        print('Checked ' + relative, flush=True)
    result = dict(passed=not errors, errors=errors, source_files=len(source),
                  destination_files=len(target), logical_bytes=sum(source.values()),
                  hashes=checked, source=str(SOURCE), destination=str(TARGET),
                  qualification='Every name/size reconciled; all published parquets and root provenance/config files hashed. Cached responses were copied by Robocopy, not individually rehashed.')
    (ROOT / 'storage_copy_verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'hashes'}, indent=2))
    if errors:
        raise SystemExit('Storage copy verification failed')


if __name__ == '__main__':
    main()
