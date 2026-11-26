"""Run against the actual native executable; loopback only, no mocked server."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import tempfile
import threading


def openssl(*args, cwd):
    subprocess.run(
        ["openssl", *args], cwd=cwd, check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30,
    )


def ca(directory, name):
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", name + ".key", "-out", name + ".pem",
            "-subj", "/CN=" + name, "-days", "1",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=directory)


def certificate(directory, name, issuer, server=False):
    ext = directory / (name + ".ext")
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=" + ("serverAuth\nsubjectAltName=IP:127.0.0.1\n" if server else "clientAuth\n"),
        encoding="ascii",
    )
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key",
            "-out", name + ".csr", "-subj", "/CN=" + name, cwd=directory)
    openssl("x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem",
            "-CAkey", issuer + ".key", "-CAserial", issuer + ".srl",
            "-CAcreateserial", "-out", name + ".pem", "-days", "1",
            "-extfile", ext.name, cwd=directory)


def prepare(directory):
    ca(directory, "trusted-ca")
    ca(directory, "foreign-ca")
    certificate(directory, "server", "trusted-ca", server=True)
    certificate(directory, "allowed", "trusted-ca")
    certificate(directory, "unpinned", "trusted-ca")
    certificate(directory, "foreign", "foreign-ca")


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def connect_and_send(directory, number, name, payload, plain=False):
    with socket.create_connection(("127.0.0.1", number), timeout=5) as sock:
        if plain:
            sock.sendall(payload)
            return
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=str(directory / "trusted-ca.pem")
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if name:
            context.load_cert_chain(directory / (name + ".pem"), directory / (name + ".key"))
        with context.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
            # Fragment the frame prefix, header and payload across writes.
            for byte in payload:
                tls.sendall(bytes([byte]))
            raw = tls.unwrap()
            raw.close()


def run_case(executable, directory, case, name, payload, expected, plain=False):
    number = port()
    pin = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert((directory / "allowed.pem").read_text())
    ).hexdigest()
    config = directory / "config.json"
    config.write_text(json.dumps({
        "bind": f"127.0.0.1:{number}",
        "server_chain": str(directory / "server.pem"),
        "server_key": str(directory / "server.key"),
        "client_ca": str(directory / "trusted-ca.pem"),
        "allowed_client_sha256": [pin],
    }), encoding="utf-8")
    process = subprocess.Popen(
        [str(executable), "syslog-tls-once", str(config), "--confirm"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    ready = queue.Queue()
    # No readiness TCP probe: the listener accepts one peer only.
    threading.Thread(target=lambda: ready.put(process.stderr.readline()), daemon=True).start()
    client_error = None
    try:
        line = ready.get(timeout=10)
        if "menunggu satu koneksi" not in line:
            raise AssertionError(f"{case}: server did not reach readiness")
        try:
            connect_and_send(directory, number, name, payload, plain)
        except (ssl.SSLError, OSError) as error:
            client_error = type(error).__name__
        stdout, stderr = process.communicate(timeout=25)
        if expected:
            assert process.returncode == 0 and client_error is None, (case, stderr, client_error)
            report = json.loads(stdout)
            assert report["transport"] == "mutual_tls"
            assert report["peer_certificate_sha256"] == pin
            assert report["accepted"] == 2 and report["rejected"] == 0
            assert "PRIVATE" not in stdout
        else:
            assert process.returncode != 0 and not stdout.strip(), (case, stdout, stderr)
        return {"case": case, "pass": True, "exit_code": process.returncode}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    executable = args.exe.resolve(strict=True)
    if args.report.exists():
        raise FileExistsError(args.report)
    report = []
    with tempfile.TemporaryDirectory(prefix="wenet-tls-fixtures-") as temporary:
        directory = Path(temporary)
        prepare(directory)
        first = b"<13>PRIVATE fixture"
        second = b"<14>second fixture"
        valid = str(len(first)).encode() + b" " + first + str(len(second)).encode() + b" " + second
        for case, identity, payload, expected, plain in [
            ("authorized_mtls", "allowed", valid, True, False),
            ("missing_cert", None, valid, False, False),
            ("foreign_ca", "foreign", valid, False, False),
            ("same_ca_unpinned", "unpinned", valid, False, False),
            ("plaintext", None, valid, False, True),
            ("truncated_frame", "allowed", valid[:-1], False, False),
            ("invalid_length", "allowed", b"0001 x", False, False),
        ]:
            try:
                report.append(run_case(executable, directory, case, identity, payload, expected, plain))
            except Exception as error:
                report.append({"case": case, "pass": False, "error": type(error).__name__})
            print(json.dumps(report[-1]), flush=True)
    with args.report.open("x", encoding="utf-8") as out:
        json.dump(report, out, indent=2)
        out.write("\n")
    return 0 if all(entry["pass"] for entry in report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
