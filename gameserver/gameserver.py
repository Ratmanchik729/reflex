#!/usr/bin/env python3
"""
gameserver — чекер + flag-id API + submission API + scoreboard для полигона A/D.

Каждый тик:
  - для каждой команды генерит флаг, кладёт его в notes-сервис команды (POST /store),
    запоминает выданный id как текущий flag-id этой команды;
  - делает SLA-чтение (GET /note?id=) с САМОГО геймсервера — этот трафик REFLEX
    обязан игнорировать (источник в блэклисте).

API:
  GET  /flagids?team=N            -> {"service":"notes","team":N,"flagid":"...","tick":t}
  POST /submit   body = флаг      -> текстовый вердикт (как в реальных сабмиттерах)
  GET  /scoreboard                -> json: очки по командам + лог принятых сабмитов
  GET  /health                    -> ok

Команда сабмиттера определяется по IP источника (10.60.N.x -> team N).
Нельзя сдавать собственный флаг. Валиден флаг текущего и прошлого тика.

Только stdlib.
"""
import json
import os
import re
import secrets
import string
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

TICK = int(os.environ.get("TICK", "6"))
# team -> vulnbox ip
TEAMS = {
    3: "10.60.3.1",
    5: "10.60.5.1",
    7: "10.60.7.1",
    9: "10.60.9.1",
    11: "10.60.11.1",
    13: "10.60.13.1",
}
GRACE_TICKS = 1  # сколько прошлых тиков флаг ещё валиден

LOCK = threading.Lock()
TICKNO = 0
# текущий flag-id на команду: team -> flagid
FLAGIDS = {}
# flag -> {"team": owner_team, "tick": t}
FLAGS = {}
# множество уже принятых (team, flag), чтобы не засчитывать дважды
ACCEPTED = set()
SCORE = {t: 0 for t in TEAMS}
LOG = []  # записи о принятых сабмитах
FLAG_RE = re.compile(r"uralcup\{[^}]{1,80}\}")


def gen_flag():
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(18))
    return "uralcup{" + body + "=}"


def team_of_ip(ip):
    # 10.60.N.x -> N
    m = re.match(r"10\.60\.(\d+)\.\d+", ip or "")
    return int(m.group(1)) if m else None


def checker_loop():
    global TICKNO
    while True:
        TICKNO += 1
        t = TICKNO
        for team, ip in TEAMS.items():
            flag = gen_flag()
            try:
                req = urllib.request.Request(
                    f"http://{ip}:80/store",
                    data=json.dumps({"owner": "checker", "note": flag}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3) as r:
                    nid = json.loads(r.read())["id"]
            except Exception as e:
                print(f"[gs] tick {t} team {team} STORE FAIL {e}", flush=True)
                continue
            with LOCK:
                FLAGIDS[team] = nid
                FLAGS[flag] = {"team": team, "tick": t}
                # чистим старые флаги
                for f, meta in list(FLAGS.items()):
                    if t - meta["tick"] > GRACE_TICKS + 2:
                        FLAGS.pop(f, None)
            # SLA-чтение С ГЕЙМСЕРВЕРА (источник в блэклисте REFLEX)
            try:
                with urllib.request.urlopen(f"http://{ip}:80/note?id={nid}", timeout=3) as r:
                    got = r.read().decode()
                ok = FLAG_RE.search(got) is not None
            except Exception as e:
                ok = False
            print(f"[gs] tick {t} team {team} flagid={nid} sla={'OK' if ok else 'DOWN'}", flush=True)
        time.sleep(TICK)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/health":
            return self._send(200, "ok")
        if u.path == "/flagids":
            q = parse_qs(u.query)
            team = int((q.get("team") or ["0"])[0])
            with LOCK:
                fid = FLAGIDS.get(team)
                t = TICKNO
            if not fid:
                return self._send(404, "no flagid yet")
            return self._send(200, json.dumps(
                {"service": "notes", "team": team, "flagid": fid, "tick": t}),
                "application/json")
        if u.path == "/flagowner":
            # независимая проверка: какой команде принадлежит флаг и валиден ли он
            q = parse_qs(u.query)
            flag = (q.get("flag") or [""])[0]
            with LOCK:
                meta = FLAGS.get(flag)
                t = TICKNO
            if not meta:
                return self._send(404, json.dumps({"known": False}), "application/json")
            return self._send(200, json.dumps(
                {"known": True, "owner_team": meta["team"], "tick": meta["tick"],
                 "age_ticks": t - meta["tick"]}), "application/json")
        if u.path == "/scoreboard":
            with LOCK:
                out = {"tick": TICKNO, "score": dict(SCORE), "accepted": list(LOG)}
            return self._send(200, json.dumps(out, indent=2), "application/json")
        return self._send(404, "not found")

    def do_POST(self):
        u = urlsplit(self.path)
        if u.path == "/submit":
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln) if ln else b""
            flag = raw.decode(errors="replace").strip()
            src = self.client_address[0]
            steam = team_of_ip(src)
            verdict = self._judge(steam, flag)
            print(f"[gs] SUBMIT from {src} (team {steam}) flag={flag[:12]}.. -> {verdict}",
                  flush=True)
            return self._send(200, verdict + "\n")
        return self._send(404, "not found")

    def _judge(self, steam, flag):
        if steam not in TEAMS:
            return "ERR_UNKNOWN_TEAM"
        if not FLAG_RE.fullmatch(flag):
            return "ERR_FORMAT"
        with LOCK:
            meta = FLAGS.get(flag)
            if not meta:
                return "ERR_INVALID"
            if meta["team"] == steam:
                return "ERR_OWN_FLAG"
            if TICKNO - meta["tick"] > GRACE_TICKS:
                return "ERR_OLD"
            key = (steam, flag)
            if key in ACCEPTED:
                return "ERR_DUP"
            ACCEPTED.add(key)
            SCORE[steam] += 1
            LOG.append({
                "tick": TICKNO,
                "attacker_team": steam,
                "victim_team": meta["team"],
                "flag": flag,
            })
            return "ACCEPTED"


if __name__ == "__main__":
    threading.Thread(target=checker_loop, daemon=True).start()
    port = int(os.environ.get("PORT", "80"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    print(f"[gs] gameserver :{port} TICK={TICK}s teams={list(TEAMS)}", flush=True)
    srv.serve_forever()
