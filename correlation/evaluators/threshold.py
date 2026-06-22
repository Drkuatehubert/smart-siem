"""evaluators/threshold.py — Règles à seuil (RF-COR-01)"""
from datetime import datetime, timezone, timedelta
class ThresholdEvaluator:
    def __init__(self, es): self.es = es
    async def evaluate(self, rule: dict):
        cond = rule.get("condition", {}); window = rule.get("fenetre_temporelle_s", 60)
        now = datetime.now(timezone.utc); since = (now - timedelta(seconds=window)).isoformat()
        must = [{"range":{"timestamp":{"gte":since}}}]
        if cond.get("field") and cond.get("value"):
            must.append({"term":{cond["field"]:cond["value"]}})
        res = await self.es.search(index="idx-logs",body={"query":{"bool":{"must":must}},"size":cond.get("threshold",5)+10})
        hits = res["hits"]["hits"]; count = res["hits"]["total"]["value"]
        if count >= cond.get("threshold", 5):
            return True, [h["_id"] for h in hits[:cond.get("threshold",5)]]
        return False, []
