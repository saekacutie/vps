#!/usr/bin/env python3
"""Minimal threaded TCP forwarder: 0.0.0.0:$LISTEN_PORT -> $TARGET_HOST:$TARGET_PORT.

Used so the admin API can keep its loopback-only bind (security model in
admin-api.py) while still serving Cloud Run's $PORT on all interfaces.
Stdlib only.
"""
import argparse
import socket
import threading


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


def handle(client, target_host, target_port):
    try:
        upstream = socket.create_connection((target_host, target_port), timeout=10)
    except OSError:
        client.close()
        return
    t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-port", type=int, required=True)
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, required=True)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.listen_port))
    srv.listen(128)
    print(f"[port-forward] listening on 0.0.0.0:{args.listen_port} "
          f"-> {args.target_host}:{args.target_port}", flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle,
                         args=(client, args.target_host, args.target_port),
                         daemon=True).start()


if __name__ == "__main__":
    main()
