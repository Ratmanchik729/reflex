#!/usr/bin/env python3
"""
notes — уязвимый stored-flag сервис для полигона A/D.

API:
  POST /store   {"owner": "...", "note": "..."}   -> {"id": "<hex16>"}
  GET  /note?id=<id>                               -> тело заметки (ТУТ БАГ: нет проверки владельца)
  GET  /health                                     -> ok

Баг (IDOR): /note отдаёт любую заметку по id без токена/проверки владельца.
Чекер кладёт флаг в заметку, её id публикуется геймсервером как flag-id.
Атакующий, зная flag-id, читает чужой флаг. Эксплойт host-agnostic по телу,
но ПРИВЯЗАН к flag-id жертвы — поэтому при реплее id надо подменять.

Только stdlib.
"""
import base64
import json
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

LOCK = threading.Lock()
NOTES = {}  # id -> {"owner": str, "note": str}
LAST_FLAG = {"v": ""}  # последний положенный чекером флаг (как содержимое "файла")
NAME = os.environ.get("TEAM_NAME", "vulnbox")

# наивные признаки SQL-инъекции (симуляция уязвимого WHERE owner='<q>')
SQLI = re.compile(r"(?i)(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|or\s+1\s*=\s*1|--|#)")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # тихо
        pass

    def _send(self, code, body, ctype="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "notes/1.0 (" + NAME + ")")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/health":
            return self._send(200, "ok")
        if u.path == "/note":
            # IDOR #1: flag-id в query-параметре  /note?id=<id>
            q = parse_qs(u.query)
            nid = (q.get("id") or [""])[0]
            return self._lookup(nid)
        if u.path.startswith("/v2/read/"):
            # IDOR #2: flag-id в СЕГМЕНТЕ ПУТИ  /v2/read/<id>
            nid = u.path[len("/v2/read/"):]
            return self._lookup(nid)
        if u.path == "/search":
            # SQLi: симуляция уязвимого `SELECT note FROM notes WHERE owner='<q>'`
            q = (parse_qs(u.query).get("q") or [""])[0]
            with LOCK:
                rows = list(NOTES.values())
            if SQLI.search(q):
                # инъекция -> дамп ВСЕХ заметок (с флагами). flag-id не нужен.
                body = "\n".join(r["note"] for r in rows)
                return self._send(200, body or "(empty)")
            # нормальный путь: только свои заметки по точному owner
            body = "\n".join(r["note"] for r in rows if r["owner"] == q)
            return self._send(200, body or "(no rows)")
        if u.path == "/download":
            # LFI / PHP-wrapper: path traversal к "файлу с флагом"
            f = (parse_qs(u.query).get("file") or [""])[0]
            with LOCK:
                flag = LAST_FLAG["v"]
            if "php://filter" in f and "flags/current" in f:
                # php://filter/convert.base64 -> отдаём base64 (НЕ плейнтекст-флаг)
                return self._send(200, base64.b64encode(flag.encode()).decode())
            if "flags/current" in f or f.endswith("/flags") or "../" in f and "flag" in f:
                return self._send(200, flag or "(no flag file)")
            if "etc/passwd" in f:
                return self._send(200, "root:x:0:0:root:/root:/bin/sh\n")
            return self._send(404, "file not found")
        if u.path == "/echo":
            # Reflected XSS: msg отражается в HTML без экранирования. Флага НЕ отдаёт.
            msg = (parse_qs(u.query).get("msg") or [""])[0]
            return self._send(200, f"<html><body>you said: {msg}</body></html>",
                              "text/html")
        return self._send(404, "not found")

    def _lookup(self, nid):
        with LOCK:
            rec = NOTES.get(nid)
        # БАГ: никакой проверки владельца/токена
        if rec is None:
            return self._send(404, "no such note")
        return self._send(200, rec["note"])

    def do_POST(self):
        u = urlsplit(self.path)
        if u.path == "/store":
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln) if ln else b""
            try:
                data = json.loads(raw or b"{}")
            except Exception:
                return self._send(400, "bad json")
            owner = str(data.get("owner", "anon"))[:64]
            note = str(data.get("note", ""))[:512]
            nid = secrets.token_hex(8)  # 16 hex -> не совпадает с форматом флага
            with LOCK:
                NOTES[nid] = {"owner": owner, "note": note}
                if owner == "checker":
                    LAST_FLAG["v"] = note  # «файл с флагом» для LFI-ветки
                # не растём бесконечно
                if len(NOTES) > 5000:
                    for k in list(NOTES)[:1000]:
                        NOTES.pop(k, None)
            return self._send(200, json.dumps({"id": nid}), "application/json")
        if u.path == "/lookup":
            # IDOR #3: flag-id в ТЕЛЕ POST  {"ref": "<id>"}
            ln = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(ln) if ln else b""
            try:
                data = json.loads(raw or b"{}")
            except Exception:
                return self._send(400, "bad json")
            return self._lookup(str(data.get("ref", "")))
        return self._send(404, "not found")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    print(f"[svc] {NAME} listening :{port}", flush=True)
    srv.serve_forever()
