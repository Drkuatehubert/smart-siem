"""ueba/risk_scorer.py — Score de risque dynamique (seuil 80 ? alerte)"""
async def compute_risk_score(es, entity_id: str, anomaly_result: dict) -> int:
    score = anomaly_result.get("score", 0)
    if score >= 80:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        await es.index(index="idx-alerts",document={"niveau":"HIGH","statut":"ouvert","score_risque":score,"commentaires":f"UEBA: {', '.join(anomaly_result.get('reasons',[]))}","created_at":now,"updated_at":now,"log_refs":[],"rule_id":"ueba-detection"})
    return score
