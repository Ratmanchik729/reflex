#!/usr/bin/env python3
"""Замер задержки нашего сервиса: доказать, что пассивный сниффинг REFLEX
не добавляет latency в хот-пат. Шлёт N запросов GET /health и печатает перцентили."""
import os
import sys
import time
import urllib.request

TARGET = os.environ.get("TARGET", "10.60.13.1")
N = int(os.environ.get("N", "500"))
LABEL = os.environ.get("LABEL", "probe")


def main():
    lat = []
    ok = 0
    url = f"http://{TARGET}:80/health"
    for _ in range(N):
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                r.read()
            ok += 1
        except Exception:
            pass
        lat.append((time.perf_counter() - t0) * 1000.0)
    lat.sort()

    def pct(p):
        return lat[min(len(lat) - 1, int(len(lat) * p))]

    print(f"[{LABEL}] target={TARGET} n={N} ok={ok} "
          f"p50={pct(0.50):.2f}ms p90={pct(0.90):.2f}ms "
          f"p99={pct(0.99):.2f}ms max={lat[-1]:.2f}ms", flush=True)


if __name__ == "__main__":
    main()
