#!/usr/bin/env python3
"""Generate a standalone sing-box HY2/TUIC server chained to a y-gate SOCKS5 endpoint."""
import argparse
import json
import os
import secrets
import uuid
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True, help="Public hostname clients connect to; certificate must cover it")
    p.add_argument("--upstream", required=True, help="y-gate authenticated SOCKS5 URL, e.g. socks5://user:pass@127.0.0.1:1080")
    p.add_argument("--cert", default="/etc/sing-box/certs/fullchain.pem")
    p.add_argument("--key", default="/etc/sing-box/certs/privkey.pem")
    p.add_argument("--hy2-port", type=int, default=8443)
    p.add_argument("--tuic-port", type=int, default=8444)
    p.add_argument("--password", default=os.environ.get("PROXY_PASSWORD") or secrets.token_urlsafe(24))
    p.add_argument("--uuid", default=os.environ.get("PROXY_UUID") or str(uuid.uuid4()))
    p.add_argument("--output", default="./config.json")
    a = p.parse_args()

    u = urlsplit(a.upstream)
    if u.scheme not in ("socks5", "socks5h") or not u.hostname:
        p.error("--upstream must be socks5://[user:password@]host:port")
    try:
        upstream_port = u.port or 1080
    except ValueError:
        p.error("invalid upstream port")
    for name, port in (("hy2", a.hy2_port), ("tuic", a.tuic_port), ("upstream", upstream_port)):
        if not 1 <= port <= 65535:
            p.error(f"{name} port must be between 1 and 65535")
    if a.hy2_port == a.tuic_port:
        p.error("HY2 and TUIC must use different UDP ports")
    if not a.host.strip() or "://" in a.host or "/" in a.host:
        p.error("--host should be a hostname or IP only, without scheme/path")

    outbound = {"type": "socks", "tag": "y-gate-socks", "server": u.hostname,
                "server_port": upstream_port, "version": "5"}
    if u.username is not None:
        outbound["username"] = unquote(u.username)
        outbound["password"] = unquote(u.password or "")
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {"type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": a.hy2_port,
             "users": [{"password": a.password}],
             "tls": {"enabled": True, "certificate_path": a.cert, "key_path": a.key}},
            {"type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": a.tuic_port,
             "users": [{"uuid": a.uuid, "password": a.password}], "congestion_control": "bbr",
             "tls": {"enabled": True, "certificate_path": a.cert, "key_path": a.key}},
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "y-gate-socks"},
    }
    Path(a.output).write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    host = a.host.strip().strip("[]")
    authority = f"[{host}]" if ":" in host else host
    sni = quote(host, safe="")
    print(f"Wrote {a.output}")
    print("Hysteria2: " + f"hysteria2://{quote(a.password, safe='')}@{authority}:{a.hy2_port}/?sni={sni}#y-gate-Hysteria2")
    print("TUIC:      " + f"tuic://{quote(a.uuid, safe='')}:{quote(a.password, safe='')}@{authority}:{a.tuic_port}?congestion_control=bbr&udp_relay_mode=native&sni={sni}#y-gate-TUIC")
    print("Keep config.json and these links private; they include credentials.")


if __name__ == "__main__":
    main()
