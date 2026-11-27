"""Executable acceptance: real TLS, before EOF, concurrent peer and changed material."""
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
from tls_interop import prepare, port

def config(directory,number):
    def digest(name):
        return hashlib.sha256((directory/name).read_bytes()).hexdigest()
    return {"bind":f"127.0.0.1:{number}",
            "server_chain":str(directory/"server.pem"),"server_key":str(directory/"server.key"),
            "client_ca":str(directory/"trusted-ca.pem"),
            "allowed_client_sha256":[hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory/"allowed.pem").read_text())).hexdigest()],
            "material":{"server_chain":digest("server.pem"),"server_key":digest("server.key"),
                        "client_ca":digest("trusted-ca.pem"),"client_crl":None}}

def stream(exe,directory):
    number=port()
    cfg=config(directory,number)
    child=subprocess.Popen([str(exe),"syslog-tls-collect","--confirm"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    events=queue.Queue()
    ready=queue.Queue()
    def drain():
        for line in child.stdout:
            events.put(json.loads(line))
    threading.Thread(target=drain,daemon=True).start()
    threading.Thread(target=lambda:ready.put(child.stderr.readline()),daemon=True).start()
    def connect():
        ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=str(directory/"trusted-ca.pem"))
        ctx.load_cert_chain(directory/"allowed.pem",directory/"allowed.key")
        return ctx.wrap_socket(socket.create_connection(("127.0.0.1",number),timeout=8),server_hostname="127.0.0.1")
    try:
        child.stdin.write(json.dumps(cfg));child.stdin.close()
        assert "collector streaming" in ready.get(timeout=10)
        with connect() as first,connect() as second:
            first.sendall(b"5 <13>x")
            a=events.get(timeout=8)
            assert a["transport"]=="mutual_tls" and a["accepted"]==1 and a["stream"]["batch"]==1
            second.sendall(b"5 <14>y"*64)
            b=events.get(timeout=8)
            assert b["accepted"]==64 and b["stream"]["connection"]!=a["stream"]["connection"]
            first.sendall(b"5 <13>z")
            c=events.get(timeout=8)
            assert c["accepted"]==1 and c["stream"]["connection"]==a["stream"]["connection"] and c["stream"]["batch"]==2
            first.sendall(b"6 <13>")
            try:
                first.unwrap().close()
            except OSError:
                pass
            d=events.get(timeout=8)
            assert d["transport"]=="tls_rejected" and "peer_certificate_sha256" not in d
        return {"before_eof":True,"concurrent_peer":True,"ordered_batches":True,"truncated_suffix_rejected":True}
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)

def mismatch(exe,directory):
    cfg=config(directory,port())
    cfg["material"]["client_ca"]="0"*64
    child=subprocess.run([str(exe),"syslog-tls-collect","--confirm"],input=json.dumps(cfg),
        capture_output=True,text=True,timeout=10)
    assert child.returncode!=0 and not child.stdout.strip() and "collector streaming" not in child.stderr
    return True

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--exe",required=True,type=Path)
    parser.add_argument("--report",required=True,type=Path)
    args=parser.parse_args()
    exe=args.exe.resolve(strict=True)
    result={}
    with tempfile.TemporaryDirectory(prefix="wenet-stream-fixture-") as tmp:
        directory=Path(tmp);prepare(directory)
        try:
            result.update(stream(exe,directory))
            result["material_mismatch_rejected"]=mismatch(exe,directory)
            result["pass"]=True
        except Exception as e:
            result["pass"]=False;result["error"]=type(e).__name__
    with args.report.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2);f.write("\n")
    return 0 if result["pass"] else 1
if __name__=="__main__":
    raise SystemExit(main())
