"""
scripts/seed_rules.py — Import des règles MITRE depuis YAML dans ES

Responsable : Ingénieur Data + Chef de Projet (sécurité)

Idempotent : PUT /idx-correlation-rules/_doc/<id> (refresh=wait_for).
Valide chaque YAML via `correlation.rule_loader.load_rule_file` (Pydantic).
Refuse d'importer un YAML invalide (exit code non nul).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Permet l'import des modules `app.*` et `correlation.*`
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

import yaml  # noqa: E402
from elasticsearch import AsyncElasticsearch  # noqa: E402

from app.config import settings  # noqa: E402
from correlation.rule_loader import RuleSchema  # noqa: E402


async def main() -> None:
    es = AsyncElasticsearch(
        hosts=[settings.ELASTICSEARCH_HOST],
        basic_auth=(settings.ELASTICSEARCH_USERNAME, settings.ELASTICSEARCH_PASSWORD),
        verify_certs=settings.ELASTICSEARCH_TLS_VERIFY,
    )

    rules_dir = ROOT / "correlation" / "rules"
    files = sorted(rules_dir.glob("*.yaml"))
    print(f"[seed_rules] {len(files)} fichier(s) YAML trouvé(s)")

    ok = 0
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                raw = yaml.safe_load(fp)
            rule = RuleSchema.model_validate(raw).model_dump()
            rule_id = rule["id"]
            await es.index(
                index="idx-correlation-rules",
                id=rule_id,
                document=rule,
                refresh="wait_for",
            )
            print(f"  ✓ {rule_id:<40s}  MITRE {rule.get('mitre_technique_id')}  [{rule.get('niveau_alerte_genere')}]")
            ok += 1
        except Exception as exc:
            print(f"  ✗ {f.name}: {exc}")
            sys.exit(1)

    await es.close()
    print(f"\n{ok}/{len(files)} règles importées.")


if __name__ == "__main__":
    asyncio.run(main())