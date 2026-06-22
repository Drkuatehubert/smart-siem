"""agent_linux/agent.py — Agent de collecte Linux"""
import time,os,json,requests,logging
API_URL=os.getenv("SIEM_API_URL","http://backend:8000"); TOKEN=os.getenv("SIEM_TOKEN","")
WATCH_FILES=["/var/log/auth.log","/var/log/syslog","/var/log/nginx/access.log"]
logger=logging.getLogger("siem-agent-linux")
def tail(path, n=50):
    try:
        with open(path) as f: lines=f.readlines(); return lines[-n:]
    except: return []
def send_log(msg, host, log_file):
    try:
        requests.post(f"{API_URL}/api/v1/logs/ingest",json={"raw_message":msg.strip(),"host":host,"source_ip":"127.0.0.1","log_type":"systeme","severity":"info"},headers={"Authorization":f"Bearer {TOKEN}"},timeout=5)
    except Exception as e: logger.error("Envoi échoué: %s",e)
if __name__=="__main__":
    import socket; host=socket.gethostname()
    logging.basicConfig(level=logging.INFO); logger.info("Agent Linux démarré sur %s",host)
    seen={f:0 for f in WATCH_FILES}
    while True:
        for f in WATCH_FILES:
            lines=tail(f)
            for i,l in enumerate(lines[seen[f]:],seen[f]): send_log(l,host,f)
            seen[f]=len(lines)
        time.sleep(5)
