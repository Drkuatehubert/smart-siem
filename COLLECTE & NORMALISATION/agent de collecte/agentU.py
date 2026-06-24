#!/usr/bin/env python3
"""
Smart SIEM Agent v2.2 — Version Finale Ultra-Résiliente (Production-Ready)
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

# Désactiver les alertes SSL pour les certificats auto-signés
requests.packages.urllib3.disable_warnings()

def get_local_ip() -> str:
    """Récupère l'IP locale utilisée pour joindre l'infrastructure réseau."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.100.1", 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

# Récupération du PID pour un filtrage anti-boucle précis
AGENT_PID = os.getpid()

CONFIG = {
    "api_url":        "https://192.168.100.1:443/normalize/batch",
    "api_token":      "agent-token-ubuntu-01",
    "hostname":       os.uname().nodename,
    "agent_ip":       get_local_ip(),
    "flush_interval": 5,
    "batch_size":     50,
    "retry_max":      3,
    "retry_delay":    2,  # Multiplicateur de base pour le Backoff exponentiel
    "registry_file":  "/var/tmp/smart_agent_registry.json",
    "log_files": [
        "/var/log/auth.log",
        "/var/log/syslog",
    ]
}

# Buffer d'attente en mémoire partagée
buffer = queue.Queue(maxsize=20000)

# Configuration du logging local de l'agent
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (PID " + str(AGENT_PID) + ") %(message)s")
log = logging.getLogger("smart-agent")

# Configuration de la session HTTP persistante (Keep-Alive)
session = requests.Session()
session.verify = False
session.headers.update({
    "Content-Type": "application/json",
    "Authorization": f"Bearer {CONFIG['api_token']}"
})

# Verrou pour la synchronisation des écritures sur le registre d'offsets
registry_lock = threading.Lock()

def load_offset(filepath: str) -> int:
    """Récupère le dernier offset enregistré pour éviter de renvoyer l'historique."""
    with registry_lock:
        if os.path.exists(CONFIG["registry_file"]):
            try:
                with open(CONFIG["registry_file"], "r") as f:
                    return json.load(f).get(filepath, 0)
            except Exception:
                return 0
        return 0

def save_offset(filepath: str, offset: int):
    """Enregistre de manière atomique la position de lecture actuelle."""
    with registry_lock:
        data = {}
        if os.path.exists(CONFIG["registry_file"]):
            try:
                with open(CONFIG["registry_file"], "r") as f:
                    data = json.load(f)
            except Exception:
                pass
        data[filepath] = offset
        try:
            with open(CONFIG["registry_file"], "w") as f:
                json.dump(data, f)
        except Exception as e:
            log.error(f"Impossible d'écrire dans le registre d'offsets : {e}")

def watch_file(filepath: str):
    """Léve une exception ou s'exécute en boucle pour lire un fichier de log."""
    path = Path(filepath)

    if not path.exists():
        log.warning(f"Fichier introuvable, attente de création : {filepath}")
        while not path.exists():
            time.sleep(5)

    try:
        current_inode = os.stat(filepath).st_ino
    except FileNotFoundError:
        current_inode = None

    offset = load_offset(filepath)
    
    f = open(filepath, "r", encoding="utf-8", errors="ignore")
    if offset > 0:
        f.seek(offset)
    else:
        f.seek(0, 2)  # Aller à la fin du fichier si aucun offset connu

    try:
        while True:
            # 1. Gestion de la rotation et des accès fichiers
            if path.exists():
                try:
                    new_inode = os.stat(filepath).st_ino
                    if current_inode is None:
                        current_inode = new_inode
                    elif new_inode != current_inode:
                        log.info(f"Rotation de log détectée pour {filepath}")
                        f.close()
                        f = open(filepath, "r", encoding="utf-8", errors="ignore")
                        current_inode = new_inode
                except FileNotFoundError:
                    time.sleep(CONFIG["flush_interval"])
                    continue
            else:
                time.sleep(CONFIG["flush_interval"])
                continue

            line = f.readline()
            if line:
                line = line.strip()
                if not line:
                    continue

                # 2. Filtrage anti-boucle précis (basé sur le nom de l'agent et le PID)
                if "smart-agent" in line or f"[{AGENT_PID}]" in line or "✓ logs envoyés" in line:
                    continue

                # 3. Structuration du log brut pour l'API
                log_brut = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message":   line,
                    "host":      CONFIG["hostname"],
                    "source":    CONFIG["agent_ip"],
                }
                
                try:
                    buffer.put(log_brut, timeout=1)
                    save_offset(filepath, f.tell())
                except queue.Full:
                    log.warning(f"Buffer plein ({buffer.qsize()} éléments) — log ignoré")
            else:
                time.sleep(0.5)
    finally:
        f.close()

def watch_file_resilient(filepath: str):
    """Superviseur de thread : relance automatiquement watch_file en cas de crash."""
    log.info(f"Démarrage du superviseur résilient pour : {filepath}")
    while True:
        try:
            watch_file(filepath)
        except Exception as e:
            log.critical(f"Crash inattendu du thread pour {filepath} : {e}. Réactivation programmée dans 10s...")
        time.sleep(10)

def send_batch(logs: list) -> bool:
    """Expédie le lot à la Gateway de normalisation avec un backoff exponentiel configuré."""
    base_delay = CONFIG.get("retry_delay", 2)
    
    for attempt in range(1, CONFIG["retry_max"] + 1):
        try:
            response = session.post(CONFIG["api_url"], json=logs, timeout=8)
            if response.status_code == 200:
                log.info(f"✓ {len(logs)} logs envoyés de manière sécurisée (HTTP 200)")
                return True
            else:
                log.warning(f"API Target a répondu HTTP {response.status_code} (Tentative {attempt}/{CONFIG['retry_max']})")
        except Exception as e:
            log.error(f"Erreur de liaison réseau à la tentative {attempt}/{CONFIG['retry_max']} : {e}")
        
        time.sleep(base_delay * attempt)
    return False

def flush_loop():
    """Régule l'extraction du buffer selon une stratégie taille/temps intelligente."""
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
                log.critical(f"Échec d'envoi persistant. Réinsertion de {len(batch)} logs dans le buffer.")
                for item in batch:
                    try:
                        buffer.put_nowait(item)
                    except queue.Full:
                        pass
                time.sleep(10)

if __name__ == "__main__":
    # Affichage complet des informations au démarrage de l'infrastructure de collecte
    log.info("====================================================================")
    log.info(f" Initialisation du Smart SIEM Agent v2.2")
    log.info(f"• Hostname local : {CONFIG['hostname']}")
    log.info(f"• IP Source      : {CONFIG['agent_ip']}")
    log.info(f"• API Cible      : {CONFIG['api_url']}")
    log.info(f"• Target Files   : {', '.join(CONFIG['log_files'])}")
    log.info(f"• Configuration  : Batch Size={CONFIG['batch_size']}, Interval={CONFIG['flush_interval']}s")
    log.info("====================================================================")

    # Lancement des threads de capture supervisés
    for filepath in CONFIG["log_files"]:
        t = threading.Thread(target=watch_file_resilient, args=(filepath,), daemon=True)
        t.start()

    # Lancement du thread d'évacuation réseau
    t_flush = threading.Thread(target=flush_loop, daemon=True)
    t_flush.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Arrêt contrôlé de l'agent demandé par l'opérateur.")