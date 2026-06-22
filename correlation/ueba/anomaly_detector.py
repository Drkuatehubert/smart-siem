"""ueba/anomaly_detector.py — Détection d anomalies horaires et volumétriques"""
from datetime import datetime, timezone
async def detect_anomaly(es, entity_id: str, current_hour: str, current_volume: int) -> dict:
    try:
        profile = (await es.get(index="idx-ueba-profiles",id=entity_id))["_source"]
    except: return {"score": 0, "reasons": []}
    reasons = []; score = 0
    if current_hour not in profile.get("typical_hours",[]):
        reasons.append(f"Connexion hors horaires habituels ({current_hour}h)"); score += 40
    avg = profile.get("avg_volume_per_hour", 1)
    if avg > 0 and current_volume > avg * 3:
        reasons.append(f"Volume anormal : {current_volume} vs moyenne {avg:.1f}"); score += 40
    return {"entity_id":entity_id,"score":min(score,100),"reasons":reasons,"evaluated_at":datetime.now(timezone.utc).isoformat()}
