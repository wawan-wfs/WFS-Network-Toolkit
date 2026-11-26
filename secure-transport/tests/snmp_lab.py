"""Explicit opt-in SNMPv3 lab test. Credentials read only via protected stdin."""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--confirm-authorized-lab", action="store_true", required=True)
    args = parser.parse_args()
    if sys.stdin.isatty():
        raise SystemExit("Supply credential JSON over a protected non-terminal pipe.")
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise SystemExit("Credential input too large.")
    correct = json.loads(raw)
    if set(correct) != {"username", "auth_password", "privacy_password"}:
        raise SystemExit("Invalid credential keys.")
    cases = [
        ("authpriv_valid", correct, True),
        ("wrong_auth", dict(correct, auth_password=secrets.token_hex(16)), False),
        ("wrong_privacy", dict(correct, privacy_password=secrets.token_hex(16)), False),
        ("wrong_user", dict(correct, username=secrets.token_hex(8)), False),
    ]
    rows = []
    if args.report.exists():
        raise FileExistsError(args.report)
    for name, credentials, expected in cases:
        entry = {"case": name, "pass": False}
        try:
            result = subprocess.run(
                [str(args.exe.resolve(strict=True)), "snmpv3-get", args.target, "--confirm"],
                input=json.dumps(credentials), text=True, capture_output=True, timeout=22,
            )
            entry["exit_code"] = result.returncode
            # Do not persist stdout/stderr; verify there was no credential echo.
            no_echo = all(value not in result.stdout + result.stderr for value in credentials.values())
            if expected and result.returncode == 0:
                report = json.loads(result.stdout)
                entry["pass"] = no_echo and report["security"] == "authPriv" and isinstance(report["sys_uptime_ticks"], int)
            elif not expected:
                entry["pass"] = no_echo and result.returncode != 0 and not result.stdout.strip()
        except (OSError, ValueError, subprocess.TimeoutExpired, KeyError) as error:
            entry["error"] = type(error).__name__
        rows.append(entry)
        print(json.dumps(entry), flush=True)
    with args.report.open("x", encoding="utf-8") as out:
        json.dump(rows, out, indent=2)
        out.write("\n")
    return 0 if all(entry["pass"] for entry in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
