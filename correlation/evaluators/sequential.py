"""evaluators/sequential.py — Règles séquentielles (RF-COR-02)"""
from datetime import datetime, timezone, timedelta
class SequentialEvaluator:
    def __init__(self, es): self.es = es
    async def evaluate(self, rule: dict):
        cond = rule.get("condition",{}); window = rule.get("fenetre_temporelle_s",300)
        now = datetime.now(timezone.utc); since = (now-timedelta(seconds=window)).isoformat()
        steps = cond.get("steps",[]); matched_ids = []
        for step in steps:
            res = await self.es.search(index="idx-logs",body={"query":{"bool":{"must":[{"range":{"timestamp":{"gte":since}}},{"term":{step["field"]:step["value"]}}]}},"size":1})
            if not res["hits"]["hits"]: return False,[]
            matched_ids.append(res["hits"]["hits"][0]["_id"])
        return len(matched_ids)==len(steps) and len(steps)>0, matched_ids
