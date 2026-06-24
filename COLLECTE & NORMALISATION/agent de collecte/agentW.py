#!/usr/bin/env python3
"""
Smart SIEM Agent v2.2 — Version Windows
"""

import time
import socket
import requests
import json
import threading
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
import queue

requests.packages.urllib3.disable_warnings()

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.100.1", 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

AGENT_PID = os.getpid()

CONFIG = {
    "api_url":        "https://192.168.100.1:443/normalize/batch",
    "api_token":      "agent-token-windows-01",
    "hostname":       os.environ.get("COMPUTERNAME", socket.gethostname()),
    "agent_ip":       get_local_ip(),
    "flush_interval": 5,
    "batch_size":     50,
    "retry_max":      3,
    "retry_delay":    2,
    "registry_file":  "C:\\smart-agent\\registry.json",
    "log_files": []   # pas de fichiers texte sur Windows — on utilise Event Log
}

buffer = queue.Queue(maxsize=20000)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (PID " + str(AGENT_PID) + ") %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("C:\\smart-agent\\agent.log", encoding="utf-8")
    ]
)
log = logging.getLogger("smart-agent-windows")

session = requests.Session()
session.verify = False
session.headers.update({
    "Content-Type": "application/json",
    "Authorization": f"Bearer {CONFIG['api_token']}"
})

# ============================================================
# COLLECTE WINDOWS EVENT LOG
# ============================================================

def collect_windows_events():
    """Collecte les événements de sécurité Windows via pywin32."""
    import win32evtlog
    import win32con

    # Event IDs importants pour la sécurité
    SECURITY_EVENTS = {
        4624: ("auth",   "info",     "Connexion réussie"),
        4625: ("auth",   "warning",  "Échec de connexion"),
        4648: ("auth",   "warning",  "Connexion avec credentials explicites"),
        4720: ("auth",   "warning",  "Compte utilisateur créé"),
        4726: ("auth",   "critical", "Compte utilisateur supprimé"),
        4740: ("auth",   "critical", "Compte verrouillé"),
        4756: ("auth",   "warning",  "Membre ajouté groupe sécurité"),
        4688: ("system", "info",     "Processus créé"),
        7036: ("system", "info",     "Service démarré ou arrêté"),
        1102: ("system", "critical", "Journal audit effacé"),
    }

    SOURCES = ["Security", "System", "Application"]
    last_record = {}  # tracker pour éviter les doublons

    log.info("Collecte Windows Event Log démarrée")

    while True:
        for source in SOURCES:
            try:
                hand = win32evtlog.OpenEventLog(None, source)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)

                for event in events[:10]:  # 10 derniers par source
                    event_id = event.EventID & 0xFFFF
                    record_num = event.RecordNumber

                    # Éviter les doublons
                    if last_record.get(source) == record_num:
                        continue

                    info = SECURITY_EVENTS.get(event_id)
                    if not info:
                        continue

                    log_type, severity, description = info
                    last_record[source] = record_num

                    message = f"EventID {event_id} — {description} — Source: {source}"
                    if event.StringInserts:
                        message += " — " + " | ".join(str(s) for s in event.StringInserts if s)

                    log_brut = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "message":   message,
                        "host":      CONFIG["hostname"],
                        "source":    CONFIG["agent_ip"],
                    }

                    try:
                        buffer.put_nowait(log_brut)
                    except queue.Full:
                        log.warning("Buffer plein — event ignoré")

                win32evtlog.CloseEventLog(hand)

            except Exception as e:
                log.error(f"Erreur lecture EventLog {source} : {e}")

        time.sleep(10)

# ============================================================
# SENDER — identique à la version Ubuntu
# ============================================================

def send_batch(logs: list) -> bool:
    base_delay = CONFIG.get("retry_delay", 2)
    for attempt in range(1, CONFIG["retry_max"] + 1):
        try:
            response = session.post(CONFIG["api_url"], json=logs, timeout=8)
            if response.status_code == 200:
                log.info(f"✓ {len(logs)} logs envoyés (HTTP 200)")
                return True
            else:
                log.warning(f"HTTP {response.status_code} (Tentative {attempt}/{CONFIG['retry_max']})")
        except Exception as e:
            log.error(f"Erreur réseau tentative {attempt}/{CONFIG['retry_max']} : {e}")
        time.sleep(base_delay * attempt)
    return False

def flush_loop():
    while True:
        batch = []
        start_time = time.time()
        while len(batch) < CONFIG["batch_size"] and (time.time() - start_time) < CONFIG["flush_interval"]:
            try:
                item = buffer.get(timeout=0.1)
                batch.append(item)
            except queue.Empty:
                continue
        if batch:
            if not send_batch(batch):
                log.critical(f"Échec envoi. Réinsertion de {len(batch)} logs.")
                for item in batch:
                    try:
                        buffer.put_nowait(item)
                    except queue.Full:
                        pass
                time.sleep(10)

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    log.info("====================================================================")
    log.info(f"Initialisation du Smart SIEM Agent v2.2 — Windows")
    log.info(f"• Hostname : {CONFIG['hostname']}")
    log.info(f"• IP       : {CONFIG['agent_ip']}")
    log.info(f"• API      : {CONFIG['api_url']}")
    log.info("====================================================================")

    # Thread collecte Event Log Windows
    t_events = threading.Thread(target=collect_windows_events, daemon=True)
    t_events.start()

    # Thread envoi
    t_flush = threading.Thread(target=flush_loop, daemon=True)
    t_flush.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Arrêt de l'agent.")