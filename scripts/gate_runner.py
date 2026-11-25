"""Independent release gates with durable, machine-readable evidence. No network or source writes."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
GATES = (
    ('branding', (sys.executable, 'scripts/test_branding.py'), 60),
    ('sqlite', (sys.executable, 'scripts/test_alert_schema.py'), 90),
    ('gate_runner', (sys.executable, 'scripts/test_gate_runner.py'), 60),
    ('ipam_metadata', (sys.executable, 'scripts/test_ipam_schema.py'), 60),
    ('rust_version', ('rustc', '+stable', '--version'), 30),
    ('format', ('cargo', '+stable', 'fmt', '--all', '--check'), 90),
    ('format_win32_toolkit', ('rustfmt', '+stable', '--edition', '2024', '--check', 'src/bin/native/toolkit_window.rs'), 90),
    ('format_win32_intel', ('rustfmt', '+stable', '--edition', '2024', '--check', 'src/bin/native/intelligence_window.rs', 'src/bin/native/visual_window.rs'), 90),
    ('clippy', ('cargo', '+stable', 'clippy', '--locked', '--all-targets', '--', '-D', 'warnings'), 900),
    ('unit_tests', ('cargo', '+stable', 'test', '--locked'), 900),
    ('release_build', ('cargo', '+stable', 'build', '--locked', '--release'), 1200),
)


def run_one(name, argv, timeout, root, out):
    started = time.monotonic()
    log_path = out / (name + '.log')
    code = None
    with log_path.open('wb') as log:
        try:
            result = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT,
                                    timeout=timeout, check=False, shell=False)
            code = result.returncode
            state = 'PASS' if code == 0 else 'FAIL'
        except subprocess.TimeoutExpired:
            state = 'FAIL'
            log.write(b'\nGate timed out.\n')
        except OSError as exc:
            state = 'BLOCKED'
            log.write(('Cannot launch: ' + str(exc) + '\n').encode('utf-8', errors='replace'))
    return {'gate': name, 'command': list(argv), 'status': state, 'exit_code': code,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'log': log_path.name}


def write_report(out, report):
    tmp = out / 'report.json.tmp'
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    tmp.replace(out / 'report.json')


def execute(gates, root, out, sha):
    # Refuse stale logs: each run must have a new or empty evidence directory.
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError('Evidence directory is not empty; choose a new directory.')
    report = {'commit': sha, 'started_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'platform': sys.platform, 'complete': False, 'release_gate': 'BLOCKED', 'gates': []}
    write_report(out, report)
    for name, argv, timeout in gates:
        row = run_one(name, argv, timeout, root, out)
        report['gates'].append(row)
        write_report(out, report)
        print(f"{name}: {row['status']} ({row['elapsed_seconds']}s)", flush=True)
    report['complete'] = True
    report['release_gate'] = 'PASS' if report['gates'] and all(
        row['status'] == 'PASS' for row in report['gates']) else 'FAIL'
    write_report(out, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    try:
        sha = subprocess.check_output(('git', 'rev-parse', 'HEAD'), cwd=ROOT,
                                      text=True, timeout=15).strip()
    except (OSError, subprocess.SubprocessError):
        sha = None
    expected = os.environ.get('GITHUB_SHA')
    if expected and sha != expected:
        print('Checkout does not match GITHUB_SHA.', file=sys.stderr)
        return 2
    try:
        report = execute(GATES, ROOT, args.out.resolve(), sha)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0 if report['release_gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
