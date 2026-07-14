#!/usr/bin/env python3
"""
demo_viva.py — Demostracion en vivo: Deteccion DDoS con ML
===========================================================
Captura trafico real con scapy, lo clasifica con el modelo entrenado,
y bloquea IPs atacantes via iptables (si se ejecuta con sudo).

Uso:
  Terminal 1 (sin sudo):  python3 demo_viva.py
  Terminal 1 (con sudo):  sudo python3 demo_viva.py --block
  Terminal 2:             python3 ddos.py localhost 100 60
"""
import sys
import os
import time
import json
import signal
import threading
import subprocess
import numpy as np
from collections import defaultdict
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
CAPTURE_DURATION = 60  # segundos de captura
FEATURE_NAMES = [
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s',
    ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
    'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std',
    ' Down/Up Ratio', ' Average Packet Size',
    ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
    'Init Fwd Win Byts', ' Init Bwd Win Byts',
    'Fwd Header Length.1',
    ' Subflow Fwd Bytes', ' Subflow Bwd Bytes',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'FIN Flag Count', 'ECE Flag Count',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
]

print(f"{BOLD}{CYAN}")
print("=" * 70)
print("  DEMO EN VIVO: Deteccion y Bloqueo de DDoS con Machine Learning")
print("  Dataset: CIC-DDoS2019 | Modelo: Random Forest")
print("=" * 70)
print(f"{RESET}")


def check_dependencies():
    """Verifica que todo este instalado."""
    errors = []
    try:
        import joblib
    except ImportError:
        errors.append("joblib")
    try:
        from scapy.all import sniff, IP, TCP, UDP
    except ImportError:
        errors.append("scapy")
    try:
        import sklearn
    except ImportError:
        errors.append("scikit-learn")

    if not os.path.exists(MODEL_PATH):
        errors.append(f"Modelo no encontrado: {MODEL_PATH}")
    if not os.path.exists(SCALER_PATH):
        errors.append(f"Scaler no encontrado: {SCALER_PATH}")

    if errors:
        print(f"{RED}  [!] Faltan dependencias: {', '.join(errors)}{RESET}")
        sys.exit(1)

    print(f"{GREEN}  [OK] Todas las dependencias instaladas{RESET}")


def start_http_server(port):
    """Lanza un servidor HTTP simple en un hilo separado."""
    import http.server
    import socketserver

    # Usar directorio del proyecto en vez de /tmp
    serve_dir = os.path.join(BASE_DIR, '_http_tmp')
    os.makedirs(serve_dir, exist_ok=True)
    with open(os.path.join(serve_dir, 'index.html'), 'w') as f:
        f.write('<html><body><h1>Servidor de Demo - DDoS Detection</h1></body></html>')

    original_dir = os.getcwd()
    os.chdir(serve_dir)
    handler = http.server.SimpleHTTPRequestHandler

    class QuietHandler(handler):
        def log_message(self, format, *args):
            pass

    server = socketserver.TCPServer(("", port), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    os.chdir(original_dir)
    print(f"{GREEN}  [OK] Servidor HTTP activo en puerto {port}{RESET}")
    return server


def extract_flow_features(packets_list):
    """Extrae features simplificadas de una lista de paquetes (un flujo)."""
    if not packets_list:
        return None

    from scapy.all import IP, TCP, UDP

    fwd_packets = []
    bwd_packets = []
    flags = {'SYN': 0, 'ACK': 0, 'RST': 0, 'PSH': 0, 'FIN': 0, 'ECE': 0}
    timestamps = []

    for pkt in packets_list:
        if not pkt.haslayer(IP):
            continue
        timestamps.append(float(pkt.time))

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        is_fwd = (src_ip == packets_list[0][IP].src)

        pkt_len = len(pkt)

        if pkt.haslayer(TCP):
            tcp_flags = pkt[TCP].flags
            if tcp_flags & 0x02: flags['SYN'] += 1
            if tcp_flags & 0x10: flags['ACK'] += 1
            if tcp_flags & 0x04: flags['RST'] += 1
            if tcp_flags & 0x08: flags['PSH'] += 1
            if tcp_flags & 0x01: flags['FIN'] += 1

        if is_fwd:
            fwd_packets.append(pkt_len)
        else:
            bwd_packets.append(pkt_len)

    if len(timestamps) < 2:
        return None

    # Calcular features
    duration = max(timestamps) - min(timestamps)
    total_packets = len(fwd_packets) + len(bwd_packets)
    total_bytes = sum(fwd_packets) + sum(bwd_packets)

    # Inter-arrival times
    iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

    # Forward features
    fwd_len = fwd_packets if fwd_packets else [0]
    bwd_len = bwd_packets if bwd_packets else [0]

    fwd_ias = []
    bwd_ias = []
    prev_fwd = prev_bwd = None
    for i, pkt in enumerate(packets_list):
        if not pkt.haslayer(IP):
            continue
        is_fwd = (pkt[IP].src == packets_list[0][IP].src)
        t = timestamps[i]
        if is_fwd:
            if prev_fwd is not None:
                fwd_ias.append(t - prev_fwd)
            prev_fwd = t
        else:
            if prev_bwd is not None:
                bwd_ias.append(t - prev_bwd)
            prev_bwd = t

    fwd_header_len = 0
    bwd_header_len = 0
    for pkt in packets_list:
        if pkt.haslayer(IP):
            ihl = pkt[IP].ihl * 4
            if pkt[IP].src == packets_list[0][IP].src:
                fwd_header_len += ihl
            else:
                bwd_header_len += ihl

    # SYN Flood: muchos SYN, pocos ACK
    # UDP Flood: pocos paquetes TCP, muchos UDP bytes
    # HTTP Flood: muchos PSH+ACK

    all_len = fwd_len + bwd_len
    syn_count = flags['SYN']
    psh_count = flags['PSH']
    ack_count = flags['ACK']

    features = np.zeros(77, dtype=np.float64)
    features[0]  = max(fwd_len)
    features[1]  = min(fwd_len)
    features[2]  = np.mean(fwd_len)
    features[3]  = np.std(fwd_len) if len(fwd_len) > 1 else 0
    features[4]  = max(bwd_len)
    features[5]  = min(bwd_len)
    features[6]  = np.mean(bwd_len)
    features[7]  = np.std(bwd_len) if len(bwd_len) > 1 else 0
    features[8]  = total_bytes / max(duration, 0.001)
    features[9]  = total_packets / max(duration, 0.001)
    features[10] = np.mean(iats)
    features[11] = np.std(iats) if len(iats) > 1 else 0
    features[12] = max(iats)
    features[13] = min(iats)
    features[14] = sum(fwd_ias) if fwd_ias else 0
    features[15] = np.mean(fwd_ias) if fwd_ias else 0
    features[16] = np.std(fwd_ias) if len(fwd_ias) > 1 else 0
    features[17] = max(fwd_ias) if fwd_ias else 0
    features[18] = min(fwd_ias) if fwd_ias else 0
    features[19] = sum(bwd_ias) if bwd_ias else 0
    features[20] = np.mean(bwd_ias) if bwd_ias else 0
    features[21] = np.std(bwd_ias) if len(bwd_ias) > 1 else 0
    features[22] = max(bwd_ias) if bwd_ias else 0
    features[23] = min(bwd_ias) if bwd_ias else 0
    features[24] = fwd_header_len
    features[25] = bwd_header_len
    features[26] = len(fwd_packets) / max(duration, 0.001)
    features[27] = len(bwd_packets) / max(duration, 0.001)
    features[28] = min(all_len) if all_len else 0
    features[29] = max(all_len) if all_len else 0
    features[30] = np.mean(all_len) if all_len else 0
    features[31] = np.std(all_len) if len(all_len) > 1 else 0
    features[32] = len(bwd_packets) / max(len(fwd_packets), 1)
    features[33] = total_bytes / max(total_packets, 1)
    features[34] = np.mean(fwd_len)
    features[35] = np.mean(bwd_len) if bwd_len else 0
    features[36] = 0
    features[37] = 0
    features[38] = fwd_header_len
    features[39] = sum(fwd_len)
    features[40] = sum(bwd_len)
    features[41] = syn_count
    features[42] = flags['RST']
    features[43] = psh_count
    features[44] = ack_count
    features[45] = flags['FIN']
    features[46] = flags['ECE']
    features[47] = np.mean(iats) if len(iats) > 3 else 0
    features[48] = np.std(iats) if len(iats) > 3 else 0
    features[49] = max(iats) if len(iats) > 3 else 0
    features[50] = min(iats) if len(iats) > 3 else 0
    features[51] = duration / max(total_packets, 1)
    features[52] = 0
    features[53] = duration
    features[54] = duration
    # features[55..76] se quedan en 0 (no calculables en tiempo real desde captura)

    return features


def block_ip(ip, sudo=False):
    """Bloquea una IP via iptables."""
    if not sudo:
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
    """Ejecuta el demo completo."""
    import joblib
    from scapy.all import sniff, IP, TCP, UDP, wrpcap

    # ─── Cargar modelo ───
    print(f"\n{BOLD}[1/5] Cargando modelo entrenado...{RESET}")
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    le = joblib.load(ENCODER_PATH)
    print(f"{GREEN}  [OK] Modelo cargado: {len(model.estimators_)} arboles{RESET}")
    print(f"{GREEN}  [OK] Clases: {list(le.classes_)}{RESET}")

    # ─── Verificar permisos ───
    use_sudo = os.geteuid() == 0
    if use_sudo:
        print(f"{YELLOW}  [!] Ejecutandose como ROOT — captura + bloqueo activos{RESET}")
    else:
        print(f"{RED}  [!] Sin root — scapy NO puede capturar paquetes{RESET}")
        print(f"{RED}  [!] Ejecuta con: sudo /mnt/c/Users/chris/exam_ia_venv/bin/python3 demo_viva.py{RESET}")
        sys.exit(1)

    # ─── Iniciar servidor HTTP ───
    print(f"\n{BOLD}[2/5] Iniciando servidor HTTP de prueba...{RESET}")
    server = start_http_server(TARGET_PORT)

    # ─── Iniciar captura ───
    print(f"\n{BOLD}[3/5] Iniciando captura de trafico ({CAPTURE_DURATION}s)...{RESET}")
    print(f"{YELLOW}  Ahora ejecuta en OTRA terminal: python3 ddos.py localhost 100 60{RESET}")
    print(f"{YELLOW}  O para ataque pesado: python3 ddos-heavy.py localhost 60{RESET}")
    print()

    captured_packets = []
    flows = defaultdict(list)
    alerts = []
    blocked_ips = set()

    def packet_callback(pkt):
        """Callback para cada paquete capturado."""
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].dport == TARGET_PORT or pkt[TCP].sport == TARGET_PORT:
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flow_key = (src, dst, sport, dport)
                flows[flow_key].append(pkt)
                captured_packets.append(pkt)

    # Capturar en hilo separado
    def capture_thread():
        try:
            sniff(
                iface="lo",
                prn=packet_callback,
                timeout=CAPTURE_DURATION,
                store=False
            )
        except Exception as e:
            print(f"{RED}  [!] Error en captura: {e}{RESET}")

    cap_thread = threading.Thread(target=capture_thread, daemon=True)
    cap_thread.start()

    # ─── Monitoreo en tiempo real ───
    print(f"\n{BOLD}[4/5] Monitoreando trafico y clasificando...{RESET}")
    print(f"{'─' * 70}")

    start_time = time.time()
    last_check = start_time
    sample_idx = 0

    while time.time() - start_time < CAPTURE_DURATION:
        time.sleep(2)
        now = time.time()

        if now - last_check < 3:
            continue
        last_check = now

        # Procesar flujos nuevos
        for flow_key, pkts in list(flows.items()):
            if len(pkts) < 3:
                continue

            src_ip = flow_key[0]
            elapsed = now - start_time

            # Extraer features
            features = extract_flow_features(pkts)
            if features is None:
                continue

            # Predecir
            X = features.reshape(1, -1)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            X_scaled = scaler.transform(X)
            prediction = model.predict(X_scaled)
            label = le.inverse_transform(prediction)[0]

            # Obtener probabilidades
            proba = model.predict_proba(X_scaled)[0]
            confidence = max(proba) * 100

            # Limpiar la clave del flujo procesado para no repetir
            del flows[flow_key]

            if label != 'BENIGN':
                color = RED
                action = ""
                if src_ip not in blocked_ips:
                    result = block_ip(src_ip, sudo=use_sudo)
                    blocked_ips.add(src_ip)
                    action = f" → {result}"
                else:
                    action = f" → {YELLOW}Ya bloqueada{RESET}"

                print(f"{color}{BOLD}  [{elapsed:5.1f}s] ALERTA: {label:12s} "
                      f"de {src_ip:15s} "
                      f"(confianza: {confidence:5.1f}%){RESET}{action}")

                alerts.append({
                    'time': f"{elapsed:.1f}s",
                    'source': src_ip,
                    'label': label,
                    'confidence': f"{confidence:.1f}%"
                })
            else:
                print(f"{GREEN}  [{elapsed:5.1f}s] NORMAL   de {src_ip:15s} "
                      f"(confianza: {confidence:5.1f}%){RESET}")

    # ─── Resumen ───
    cap_thread.join(timeout=5)

    print(f"\n{'─' * 70}")
    print(f"\n{BOLD}[5/5] RESUMEN DE LA DEMOSTRACION{RESET}")
    print(f"{'═' * 70}")
    print(f"  Duracion:            {CAPTURE_DURATION}s")
    print(f"  Paquetes capturados: {len(captured_packets)}")
    print(f"  IPs bloqueadas:      {len(blocked_ips)}")
    print(f"  Alertas totales:     {len(alerts)}")
    print()

    if alerts:
        # Contar por tipo de ataque
        from collections import Counter
        attack_counts = Counter(a['label'] for a in alerts)
        print(f"  {BOLD}Distribucion de ataques detectados:{RESET}")
        for attack, count in attack_counts.most_common():
            print(f"    {RED}{attack:15s}: {count} flujos detectados{RESET}")
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
            'packets_captured': len(captured_packets),
            'alerts': alerts,
            'blocked_ips': list(blocked_ips),
        }, f, indent=2)
    print(f"  Log guardado: {log_path}")
    print(f"{'═' * 70}\n")

    # Cleanup
    server.shutdown()


if __name__ == '__main__':
    check_dependencies()
    try:
        run_demo()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Demo detenido por el usuario{RESET}")
