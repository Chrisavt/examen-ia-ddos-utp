#!/usr/bin/env python3
"""
demo_viva.py — Demostracion en vivo: Deteccion DDoS con ML
==========================================================
Sistema hibrido de deteccion:
  1. Deteccion heuristica por paquete (tiempo real, funciona en localhost)
  2. Clasificacion ML (Random Forest, entrenado en CIC-DDoS2019)
  3. Bloqueo automatico via iptables

Uso:
  Terminal 1:  sudo python3 demo_viva.py [--block]
  Terminal 2:  python3 http_flood.py 127.0.0.1 8080 30
               python3 syn_flood.py 127.0.0.1 8080 50 30
"""
import sys
import os
import time
import json
import signal
import threading
import subprocess
import numpy as np
from collections import defaultdict, Counter
from datetime import datetime

# ─── Rutas ───
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, 'resultados')
MODEL_PATH = os.path.join(RESULTS_DIR, 'modelo_rf.pkl')
SCALER_PATH = os.path.join(RESULTS_DIR, 'scaler.pkl')
ENCODER_PATH = os.path.join(RESULTS_DIR, 'label_encoder.pkl')

# ─── Colores ───
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# ─── Config ───
TARGET_IP = '127.0.0.1'
TARGET_PORT = 8080
CAPTURE_DURATION = 60

# ─── Heuristica de deteccion ───
# Ventana de evaluacion (segundos)
WINDOW_SIZE = 3.0
# Umbrales para clasificar como ataque
THRESHOLDS = {
    'syn_flood':    {'syn_ratio': 0.7,  'min_packets': 10},
    'http_flood':   {'pps': 50,         'min_packets': 20},
    'udp_flood':    {'pps': 100,        'min_packets': 15},
    'rst_flood':    {'rst_ratio': 0.5,  'min_packets': 10},
}

print(f"{BOLD}{CYAN}")
print("=" * 70)
print("  DEMO EN VIVO: Deteccion y Bloqueo de DDoS con Machine Learning")
print("  Dataset: CIC-DDoS2019 | Modelo: Random Forest | Heuristica: Tiempo real")
print("=" * 70)
print(f"{RESET}")


def check_dependencies():
    errors = []
    for pkg_name, imp in [('joblib', 'joblib'), ('scapy', 'scapy'), ('sklearn', 'sklearn')]:
        try:
            __import__(imp)
        except ImportError:
            errors.append(pkg_name)
    for path, name in [(MODEL_PATH, 'modelo_rf.pkl'), (SCALER_PATH, 'scaler.pkl')]:
        if not os.path.exists(path):
            errors.append(f"{name} no encontrado")
    if errors:
        print(f"{RED}  [!] Faltan dependencias: {', '.join(errors)}{RESET}")
        sys.exit(1)
    print(f"{GREEN}  [OK] Todas las dependencias instaladas{RESET}")


def start_http_server(port):
    import http.server
    import socketserver
    serve_dir = os.path.join(BASE_DIR, '_http_tmp')
    os.makedirs(serve_dir, exist_ok=True)
    with open(os.path.join(serve_dir, 'index.html'), 'w') as f:
        f.write('<html><body><h1>Servidor de Demo - DDoS Detection</h1></body></html>')
    original_dir = os.getcwd()
    os.chdir(serve_dir)

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
        def log_error(self, format, *args):
            pass

    class QuietServer(socketserver.TCPServer):
        allow_reuse_address = True
        def handle_error(self, request, client_address):
            pass  # suprime BrokenPipeError y otros tracebacks

    server = QuietServer(("", port), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    os.chdir(original_dir)
    print(f"{GREEN}  [OK] Servidor HTTP activo en puerto {port}{RESET}")
    return server


def classify_packet(pkt):
    """Clasifica un paquete individual y retorna tipo + flags."""
    from scapy.all import IP, TCP, UDP
    info = {'type': 'OTHER', 'flags': {}, 'src': '', 'dst': '', 'len': 0, 'time': 0}
    if not pkt.haslayer(IP):
        return None
    info['src'] = pkt[IP].src
    info['dst'] = pkt[IP].dst
    info['len'] = len(pkt)
    info['time'] = float(pkt.time)

    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        info['sport'] = pkt[TCP].sport
        info['dport'] = pkt[TCP].dport
        info['flags'] = {
            'SYN': bool(flags & 0x02),
            'ACK': bool(flags & 0x10),
            'RST': bool(flags & 0x04),
            'PSH': bool(flags & 0x08),
            'FIN': bool(flags & 0x01),
        }
        if info['flags']['SYN'] and not info['flags']['ACK']:
            info['type'] = 'SYN'
        elif info['flags']['RST']:
            info['type'] = 'RST'
        elif info['flags']['PSH']:
            info['type'] = 'PSH'
        else:
            info['type'] = 'TCP'
    elif pkt.haslayer(UDP):
        info['sport'] = pkt[UDP].sport
        info['dport'] = pkt[UDP].dport
        info['type'] = 'UDP'
    else:
        return None
    return info


def detect_attack_heuristic(packet_infos, window_start):
    """Detecta ataques usando heuristica sobre ventana de tiempo."""
    window_pkts = [p for p in packet_infos if p['time'] >= window_start]
    if len(window_pkts) < 5:
        return None

    total = len(window_pkts)
    duration = max(p['time'] for p in window_pkts) - min(p['time'] for p in window_pkts)
    if duration < 0.1:
        duration = 0.1

    pps = total / duration

    syn_count = sum(1 for p in window_pkts if p['type'] == 'SYN')
    rst_count = sum(1 for p in window_pkts if p['type'] == 'RST')
    psh_count = sum(1 for p in window_pkts if p['type'] == 'PSH')
    udp_count = sum(1 for p in window_pkts if p['type'] == 'UDP')

    syn_ratio = syn_count / total if total > 0 else 0
    rst_ratio = rst_count / total if total > 0 else 0

    # SYN Flood: alta proporcion de SYN sin ACK
    t = THRESHOLDS['syn_flood']
    if syn_ratio >= t['syn_ratio'] and total >= t['min_packets']:
        return ('Syn Flood', syn_ratio * 100, f"SYN ratio: {syn_ratio:.0%}")

    # RST Flood
    t = THRESHOLDS['rst_flood']
    if rst_ratio >= t['rst_ratio'] and total >= t['min_packets']:
        return ('RST Flood', rst_ratio * 100, f"RST ratio: {rst_ratio:.0%}")

    # HTTP Flood: alto packets/s con PSH+ACK
    t = THRESHOLDS['http_flood']
    if pps >= t['pps'] and total >= t['min_packets']:
        conf = min(95, 50 + (pps - t['pps']) / t['pps'] * 45)
        return ('HTTP Flood', conf, f"PPS: {pps:.0f}")

    # UDP Flood
    t = THRESHOLDS['udp_flood']
    if pps >= t['pps'] and udp_count > total * 0.5:
        conf = min(95, 50 + (pps - t['pps']) / t['pps'] * 45)
        return ('UDP Flood', conf, f"PPS: {pps:.0f}")

    return None


def extract_flow_features_heuristic(packet_infos):
    """Extrae features simplificadas para el modelo ML."""
    if not packet_infos:
        return None

    fwd_pkts = [p for p in packet_infos if p['type'] in ('SYN', 'PSH', 'TCP')]
    bwd_pkts = [p for p in packet_infos if p['type'] in ('RST', 'ACK')]

    fwd_lens = [p['len'] for p in fwd_pkts] if fwd_pkts else [0]
    bwd_lens = [p['len'] for p in bwd_pkts] if bwd_pkts else [0]
    all_lens = [p['len'] for p in packet_infos]

    timestamps = sorted(p['time'] for p in packet_infos)
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.001

    iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)] if len(timestamps) > 1 else [0]

    syn_count = sum(1 for p in packet_infos if p['type'] == 'SYN')
    rst_count = sum(1 for p in packet_infos if p['type'] == 'RST')
    psh_count = sum(1 for p in packet_infos if p['type'] == 'PSH')
    ack_count = sum(1 for p in packet_infos if p['flags'].get('ACK', False))
    fin_count = sum(1 for p in packet_infos if p['flags'].get('FIN', False))

    features = np.zeros(77, dtype=np.float64)
    features[0]  = max(fwd_lens)
    features[1]  = min(fwd_lens)
    features[2]  = np.mean(fwd_lens)
    features[3]  = np.std(fwd_lens) if len(fwd_lens) > 1 else 0
    features[4]  = max(bwd_lens)
    features[5]  = min(bwd_lens)
    features[6]  = np.mean(bwd_lens)
    features[7]  = np.std(bwd_lens) if len(bwd_lens) > 1 else 0
    features[8]  = sum(all_lens) / max(duration, 0.001)
    features[9]  = len(packet_infos) / max(duration, 0.001)
    features[10] = np.mean(iats)
    features[11] = np.std(iats) if len(iats) > 1 else 0
    features[12] = max(iats)
    features[13] = min(iats)
    features[26] = len(fwd_pkts) / max(duration, 0.001)
    features[27] = len(bwd_pkts) / max(duration, 0.001)
    features[28] = min(all_lens)
    features[29] = max(all_lens)
    features[30] = np.mean(all_lens)
    features[31] = np.std(all_lens) if len(all_lens) > 1 else 0
    features[32] = len(bwd_pkts) / max(len(fwd_pkts), 1)
    features[33] = sum(all_lens) / max(len(all_lens), 1)
    features[41] = syn_count
    features[42] = rst_count
    features[43] = psh_count
    features[44] = ack_count
    features[45] = fin_count
    features[53] = duration
    features[54] = duration

    return features


def block_ip(ip, use_sudo=False):
    if not use_sudo:
        return f"[SIMULADO] iptables -A INPUT -s {ip} -j DROP"
    try:
        subprocess.run(
            ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, timeout=5
        )
        return f"[BLOQUEADO] iptables -A INPUT -s {ip} -j DROP"
    except Exception as e:
        return f"[ERROR] No se pudo bloquear {ip}: {e}"


def run_demo():
    import joblib
    from scapy.all import sniff, IP, TCP, UDP

    # ─── Cargar modelo ───
    print(f"\n{BOLD}[1/5] Cargando modelo entrenado...{RESET}")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(ENCODER_PATH)
    print(f"{GREEN}  [OK] Modelo cargado: {len(model.estimators_)} arboles{RESET}")
    print(f"{GREEN}  [OK] Clases: {list(le.classes_)}{RESET}")

    # ─── Verificar permisos ───
    use_sudo = os.geteuid() == 0
    use_block = '--block' in sys.argv
    if not use_sudo:
        print(f"{RED}  [!] Sin root — se necesita sudo para capturar paquetes{RESET}")
        print(f"{RED}  [!] Ejecuta: sudo python3 demo_viva.py [--block]{RESET}")
        sys.exit(1)
    print(f"{YELLOW}  [OK] Ejecutando como ROOT — captura activa{RESET}")
    if use_block:
        print(f"{YELLOW}  [OK] Bloqueo activo via iptables{RESET}")
    else:
        print(f"{YELLOW}  [!] Bloqueo SIMULADO (usa --block para activar){RESET}")

    # ─── Iniciar servidor HTTP ───
    print(f"\n{BOLD}[2/5] Iniciando servidor HTTP de prueba...{RESET}")
    server = start_http_server(TARGET_PORT)

    # ─── Estado ───
    packet_buffer = []         # todos los paquetes
    packet_infos = []          # info clasificada
    alerts_log = []
    blocked_ips = set()
    attack_counts = Counter()

    # ─── Captura ───
    print(f"\n{BOLD}[3/5] Iniciando captura de trafico ({CAPTURE_DURATION}s)...{RESET}")
    print(f"{YELLOW}  Ataques para probar (en OTRA terminal):{RESET}")
    print(f"    python3 http_flood.py {TARGET_IP} {TARGET_PORT} 30")
    print(f"    python3 syn_flood.py {TARGET_IP} {TARGET_PORT} 50 30")
    print()

    from scapy.all import sniff as scapy_sniff

    def capture_thread():
        try:
            def process_pkt(pkt):
                if pkt.haslayer(IP) and pkt.haslayer(TCP):
                    if pkt[TCP].dport == TARGET_PORT or pkt[TCP].sport == TARGET_PORT:
                        packet_buffer.append(pkt)
                        info = classify_packet(pkt)
                        if info:
                            packet_infos.append(info)

            scapy_sniff(iface="lo", prn=process_pkt, timeout=CAPTURE_DURATION, store=False)
        except Exception as e:
            print(f"{RED}  [!] Error en captura: {e}{RESET}")

    cap_thread = threading.Thread(target=capture_thread, daemon=True)
    cap_thread.start()

    # ─── Monitoreo ───
    print(f"\n{BOLD}[4/5] Monitoreando trafico y clasificando...{RESET}")
    print(f"{'─' * 70}")

    start_time = time.time()
    last_heuristic_check = start_time
    last_ml_check = start_time
    last_print = start_time
    window_start = start_time

    while time.time() - start_time < CAPTURE_DURATION:
        time.sleep(0.5)
        now = time.time()
        elapsed = now - start_time

        # ── Deteccion heuristica (cada 2s) ──
        if now - last_heuristic_check >= 2.0:
            last_heuristic_check = now
            if len(packet_infos) > 5:
                result = detect_attack_heuristic(packet_infos, window_start)
                if result:
                    attack_type, confidence, detail = result
                    # Obtener IP atacante mas comun en la ventana
                    window_pkts = [p for p in packet_infos if p['time'] >= window_start]
                    src_ips = [p['src'] for p in window_pkts]
                    attacker_ip = Counter(src_ips).most_common(1)[0][0] if src_ips else 'unknown'

                    color = RED
                    action = ""
                    if attacker_ip not in blocked_ips and use_block:
                        r = block_ip(attacker_ip, use_sudo=True)
                        blocked_ips.add(attacker_ip)
                        action = f" → {r}"
                    elif attacker_ip not in blocked_ips:
                        action = f" → [SIMULADO] iptables -A INPUT -s {attacker_ip} -j DROP"
                        blocked_ips.add(attacker_ip)

                    print(f"{color}{BOLD}  [{elapsed:5.1f}s] *** {attack_type:12s} *** "
                          f"de {attacker_ip:15s} "
                          f"(confianza: {confidence:5.1f}%) {detail}{RESET}{action}")

                    alerts_log.append({
                        'time': f"{elapsed:.1f}s",
                        'source': attacker_ip,
                        'label': attack_type,
                        'confidence': f"{confidence:.1f}%",
                        'detail': detail,
                        'method': 'heuristic'
                    })
                    attack_counts[attack_type] += 1
                    window_start = now

        # ── Clasificacion ML (cada 5s) ──
        if now - last_ml_check >= 5.0:
            last_ml_check = now
            if len(packet_buffer) >= 5:
                features = extract_flow_features_heuristic(packet_infos[-50:])
                if features is not None:
                    X = features.reshape(1, -1)
                    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
                    X_scaled = scaler.transform(X)
                    prediction = model.predict(X_scaled)
                    ml_label = le.inverse_transform(prediction)[0]
                    proba = model.predict_proba(X_scaled)[0]
                    ml_conf = max(proba) * 100

                    ml_color = RED if ml_label != 'BENIGN' else GREEN
                    print(f"  {ml_color}  [{elapsed:5.1f}s] [ML] Modelo clasifica: {ml_label:12s} "
                          f"(confianza: {ml_conf:.1f}%){RESET}")

        # ── Status periodico ──
        if now - last_print >= 5.0:
            last_print = now
            n_pkts = len(packet_infos)
            sys.stdout.write(f"\r  {CYAN}[{elapsed:5.1f}s] Paquetes: {n_pkts:5} | "
                           f"Alertas: {len(alerts_log):3} | "
                           f"Bloqueadas: {len(blocked_ips):2}{RESET}    ")
            sys.stdout.flush()

    # ─── Resumen ───
    cap_thread.join(timeout=5)
    print(f"\n")
    print(f"{'─' * 70}")
    print(f"\n{BOLD}[5/5] RESUMEN DE LA DEMOSTRACION{RESET}")
    print(f"{'═' * 70}")
    print(f"  Duracion:            {CAPTURE_DURATION}s")
    print(f"  Paquetes capturados: {len(packet_buffer)}")
    print(f"  IPs bloqueadas:      {len(blocked_ips)}")
    print(f"  Alertas totales:     {len(alerts_log)}")
    print()

    if alerts_log:
        print(f"  {BOLD}Distribucion de ataques detectados:{RESET}")
        for attack, count in attack_counts.most_common():
            print(f"    {RED}{attack:15s}: {count:3} detecciones{RESET}")
        print()

        print(f"  {BOLD}Ultimas 10 alertas:{RESET}")
        for a in alerts_log[-10:]:
            print(f"    {a['time']:>8s} | {a['label']:12s} | {a['source']:15s} | "
                  f"{a['confidence']:>6s} | {a['method']}")
        print()

        print(f"  {BOLD}IPs bloqueadas:{RESET}")
        for ip in blocked_ips:
            print(f"    {RED}BLOCKED → {ip}{RESET}")
    else:
        print(f"{GREEN}  No se detectaron ataques{RESET}")

    print(f"\n{'═' * 70}")

    # Guardar log
    os.makedirs(RESULTS_DIR, exist_ok=True)
    log_path = os.path.join(RESULTS_DIR, 'demo_log.json')
    with open(log_path, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'duration': CAPTURE_DURATION,
            'packets_captured': len(packet_buffer),
            'alerts': alerts_log,
            'blocked_ips': list(blocked_ips),
        }, f, indent=2)
    print(f"  Log guardado: {log_path}")
    print(f"{'═' * 70}\n")

    server.shutdown()


if __name__ == '__main__':
    check_dependencies()
    try:
        run_demo()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Demo detenido por el usuario{RESET}")
