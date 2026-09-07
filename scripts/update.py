from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = ROOT / "sources.yaml"
OUT = ROOT / "public" / "clash.yaml"
HISTORY = ROOT / "public" / "history"

TIMEOUT = 20
UA = "free-clash-auto-sub/1.0"


def load_sources():
    data = yaml.safe_load(SOURCE_FILE.read_text(encoding="utf-8")) or {}
    return [x for x in data.get("sources", []) if x.get("enabled", True) and x.get("url")]


def fetch(url: str) -> str:
    r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    return r.text


def maybe_b64(s: str) -> str:
    s = s.strip()
    if not s or any(c in s for c in "\r\n\t "):
        return s
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        txt = raw.decode("utf-8")
        if any(x in txt for x in ("vmess://", "vless://", "trojan://", "ss://", "hysteria2://", "proxies:")):
            return txt
    except Exception:
        pass
    return s


def parse_vmess(uri):
    raw = uri[8:]
    data = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode())
    p = {
        "name": data.get("ps") or "VMess",
        "type": "vmess",
        "server": data.get("add"),
        "port": int(data.get("port", 443)),
        "uuid": data.get("id"),
        "alterId": int(data.get("aid", 0)),
        "cipher": data.get("scy", "auto"),
    }
    net = data.get("net", "tcp")
    if net == "ws":
        p["network"] = "ws"
        p["ws-opts"] = {"path": data.get("path") or "/"}
        if data.get("host"):
            p["ws-opts"]["headers"] = {"Host": data["host"]}
    if data.get("tls") in ("tls", True):
        p["tls"] = True
        if data.get("sni"):
            p["servername"] = data["sni"]
    return p


def parse_ss(uri):
    body = uri[5:]
    if "@" not in body:
        decoded = base64.b64decode(body.split("#")[0] + "=" * (-len(body.split("#")[0]) % 4)).decode()
    else:
        decoded = body.split("#")[0]
        decoded = unquote(decoded)
    name = unquote(uri.split("#", 1)[1]) if "#" in uri else "SS"
    userinfo, hostport = decoded.rsplit("@", 1)
    cipher, password = userinfo.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    return {
        "name": name,
        "type": "ss",
        "server": host,
        "port": int(port),
        "cipher": cipher,
        "password": password,
    }


def parse_generic(uri):
    u = urlparse(uri)
    scheme = u.scheme.lower()
    q = parse_qs(u.query)
    name = unquote(u.fragment) if u.fragment else scheme.upper()
    if scheme in ("vless", "trojan", "hysteria2", "hy2"):
        p = {
            "name": name,
            "type": "hysteria2" if scheme in ("hysteria2", "hy2") else scheme,
            "server": u.hostname,
            "port": u.port or 443,
        }
        if scheme == "vless":
            p["uuid"] = u.username
            if q.get("type", [""])[0] == "ws":
                p["network"] = "ws"
                p["ws-opts"] = {"path": q.get("path", ["/"])[0]}
                if q.get("host"):
                    p["ws-opts"]["headers"] = {"Host": q["host"][0]}
            if q.get("security", [""])[0] in ("tls", "reality"):
                p["tls"] = True
            if q.get("sni"):
                p["servername"] = q["sni"][0]
            if q.get("fp"):
                p["client-fingerprint"] = q["fp"][0]
        elif scheme == "trojan":
            p["password"] = u.username or ""
            if q.get("sni"):
                p["sni"] = q["sni"][0]
            p["tls"] = True
        else:
            p["password"] = u.username or unquote(u.password or "")
            if q.get("sni"):
                p["sni"] = q["sni"][0]
        return p
    return None


def parse_text(text):
    text = maybe_b64(text)
    text = text.strip()
    if not text:
        return []

    # Clash/Mihomo YAML
    try:
        obj = yaml.safe_load(text)
        if isinstance(obj, dict) and isinstance(obj.get("proxies"), list):
            return [x for x in obj["proxies"] if isinstance(x, dict) and x.get("server")]
    except Exception:
        pass

    # JSON with proxies
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and isinstance(obj.get("proxies"), list):
            return [x for x in obj["proxies"] if isinstance(x, dict) and x.get("server")]
    except Exception:
        pass

    result = []
    for line in text.splitlines():
        line = line.strip().strip("'").strip('"')
        if not line:
            continue
        try:
            if line.startswith("vmess://"):
                result.append(parse_vmess(line))
            elif line.startswith("ss://"):
                result.append(parse_ss(line))
            elif line.startswith(("vless://", "trojan://", "hysteria2://", "hy2://")):
                p = parse_generic(line)
                if p:
                    result.append(p)
        except Exception:
            continue
    return result


def fingerprint(p):
    stable = {
        "type": p.get("type"),
        "server": p.get("server"),
        "port": p.get("port"),
        "uuid": p.get("uuid"),
        "password": p.get("password"),
        "cipher": p.get("cipher"),
        "network": p.get("network"),
        "servername": p.get("servername") or p.get("sni"),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def clean_name(name):
    name = str(name or "Node").strip()
    name = re.sub(r"[\r\n\t]+", " ", name)
    return name[:80]


def normalize(proxies):
    seen = set()
    result = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        if not p.get("server") or not p.get("port") or not p.get("type"):
            continue
        p = dict(p)
        p["name"] = clean_name(p.get("name"))
        fp = fingerprint(p)
        if fp in seen:
            continue
        seen.add(fp)
        result.append(p)
    return result


def make_config(proxies):
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "profile": {"store-selected": True},
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "自动选择",
                "type": "url-test",
                "proxies": names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
            },
            {
                "name": "手动选择",
                "type": "select",
                "proxies": ["自动选择", "DIRECT"] + names,
            },
        ],
        "rules": [
            "GEOSITE,CN,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,自动选择",
        ],
    }


def main():
    all_nodes = []
    for src in load_sources():
        try:
            text = fetch(src["url"])
            nodes = parse_text(text)
            print(f"[OK] {src['name']}: {len(nodes)} nodes")
            all_nodes.extend(nodes)
        except Exception as e:
            print(f"[WARN] {src['name']}: {e}")

    nodes = normalize(all_nodes)
    print(f"[TOTAL] unique nodes: {len(nodes)}")

    config = make_config(nodes)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
    )

    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    HISTORY.mkdir(parents=True, exist_ok=True)
    (HISTORY / f"{day}.yaml").write_text(
        yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
