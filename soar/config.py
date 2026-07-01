import os
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent.parent
load_dotenv(ROOT_DIR / ".env")

# pfSense
PFSENSE_HOST = os.getenv("PFSENSE_HOST")
PFSENSE_USER = os.getenv("PFSENSE_USER")
PFSENSE_PASSWORD = os.getenv("PFSENSE_PASSWORD")
PFSENSE_SSH_KEY = os.getenv("PFSENSE_SSH_KEY")
PFSENSE_PORT = int(os.getenv("PFSENSE_PORT", "22"))

# Active Directory
AD_HOST = os.getenv("AD_HOST")
AD_PORT = int(os.getenv("AD_PORT", "389"))
AD_USER = os.getenv("AD_USER")
AD_PASSWORD = os.getenv("AD_PASSWORD")
AD_BASE_DN = os.getenv("AD_BASE_DN")
AD_TARGET_OU = os.getenv("AD_TARGET_OU")

# Elasticsearch
ES_HOST = os.getenv("ES_HOST")
ES_BLOCKED_INDEX = os.getenv("ES_BLOCKED_INDEX")

# Celery
CELERY_BROKER = os.getenv("CELERY_BROKER")

# SOAR
CONFIRM_DELAY_SECONDS = int(os.getenv("CONFIRM_DELAY_SECONDS", "60"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "60"))

# Alert IDs annulés avant exécution (mode CONFIRM) — état en mémoire
CANCELLED_ALERTS: set = set()
