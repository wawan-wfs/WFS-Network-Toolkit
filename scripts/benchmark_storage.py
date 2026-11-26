"""Run the real ignored Rust archive benchmark three times, never in normal CI."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = []
    for run in range(1, 4):
        start = time.monotonic()
        command = ["cargo", "test", "--locked", "--release", "benchmark_archive_million",
                   "--", "--ignored", "--exact", "--nocapture"]
        # The exact fully-qualified test name is not stable across crate layout.
        command.remove("--exact")
        with (args.out / f"run-{run}.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=3600, check=False)
        raw = (args.out / f"run-{run}.log").read_text(encoding="utf-8")
        matches = re.findall(r"rows=1000000 scopes=10 elapsed_ms=\d+ rows_per_sec=\d+ db_bytes=\d+ wal_bytes=\d+ p50_inspect_us=\d+ p95_inspect_us=\d+ p99_inspect_us=\d+", raw)
        report.append({"run": run, "exit_code": result.returncode,
                       "elapsed_s": round(time.monotonic() - start, 3),
                       "measurement": matches[0] if len(matches) == 1 else None,
                       "pass": result.returncode == 0 and len(matches) == 1})
        (args.out / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                              encoding="utf-8")
        if not report[-1]["pass"]:
            return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
