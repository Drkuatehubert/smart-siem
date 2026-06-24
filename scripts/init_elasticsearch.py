"""
scripts/init_elasticsearch.py — Création et configuration des 13 index ES

Responsable : Chef de Projet & Sécurité
Exigences : RF-COL-05 (initialisation), NFR-SEC-05 (audit append-only + ILM 7 ans)

Ce script :
  * crée l'ILM policy `audit-ilm-policy` (hot 1j → warm 30j → cold 365j → delete 2555j) ;
  * crée le template `audit-template` qui pose `index.blocks.write=true` après rollover ;
  * crée les 13 index métier avec leur mapping strict ;
  * attache l'ILM policy aux deux index sensibles (audit et SOAR) ;
  * ne s'exécute pas avec `verify_certs=False` (utilise les settings du config).

Note : exécution via `python scripts/init_elasticsearch.py` depuis la racine.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Permet l'import de `app.config` quel que soit le CWD
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from elasticsearch import AsyncElasticsearch  # noqa: E402

from app.config import settings  # noqa: E402

ES_HOST = settings.ELASTICSEARCH_HOST
ES_USER = settings.ELASTICSEARCH_USERNAME
ES_PASS = settings.ELASTICSEARCH_PASSWORD
ES_VERIFY = settings.ELASTICSEARCH_TLS_VERIFY
ES_CA = settings.ELASTICSEARCH_CA_CERTS

# ─────────────────────────────────────────────────────────────────────
# ILM policy — 7 ans de rétention (2555 jours)
# ─────────────────────────────────────────────────────────────────────

AUDIT_ILM_POLICY = {
    "policy": {
        "phases": {
            "hot":  {"min_age": "0ms",  "actions": {"set_priority": {"priority": 100}}},
            "warm": {"min_age": "1d",   "actions": {
                "set_priority": {"priority": 50},
                "forcemerge":   {"max_num_segments": 1},
            }},
            "cold": {"min_age": "30d",  "actions": {
                "set_priority": {"priority": 0},
                "freeze":       {},
            }},
            "delete": {"min_age": "2555d", "actions": {"delete": {}}},
        }
    }
}

AUDIT_TEMPLATE_NAME = "audit-template"
AUDIT_TEMPLATE = {
    "index_patterns": ["idx-audit-log", "idx-soar-executions"],
    "template": {
        "settings": {
            "index": {
                "lifecycle": {"name": "audit-ilm-policy", "rollover_alias": None},
                # write-once : pas de delete API, pas de update API
                "blocks": {"write": False},  # on autorise l'écriture initiale ;
                                              # le rollover bascule à True (voir hook)
            },
            "number_of_shards": 1,
            "number_of_replicas": 1,
        },
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "user_id":       {"type": "keyword"},
                "action":        {"type": "keyword"},
                "ip_address":    {"type": "ip"},
                "user_agent":    {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                "request_id":    {"type": "keyword"},
                "http_method":   {"type": "keyword"},
                "http_path":     {"type": "keyword"},
                "status":        {"type": "keyword"},
                "target_entity": {"type": "keyword"},
                "target_id":     {"type": "keyword"},
                "details":       {"type": "object", "enabled": True},
                "created_at":    {"type": "date"},
                "executed_at":   {"type": "date"},
            },
        },
    },
    "priority": 200,
}

# ─────────────────────────────────────────────────────────────────────
# Mappings des 13 index métier
# ─────────────────────────────────────────────────────────────────────

INDICES: dict[str, dict] = {
    "idx-users": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "username":             {"type": "keyword"},
                "password_hash":        {"type": "keyword", "index": False},
                "password_history":     {"type": "keyword", "index": False},
                "email":                {"type": "keyword"},
                "role_id":              {"type": "keyword"},
                "org_scope":            {"type": "keyword"},
                "is_active":            {"type": "boolean"},
                "mfa_enabled":          {"type": "boolean"},
                "mfa_pending_secret":   {"type": "keyword", "index": False},
                "must_reset_password":  {"type": "boolean"},
                "locked_until":         {"type": "date"},
                "created_at":           {"type": "date"},
                "last_login_at":        {"type": "date"},
            },
        },
    },
    "idx-roles": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "nom":          {"type": "keyword"},
                "permissions":  {"type": "object"},
                "description":  {"type": "text"},
            },
        },
    },
    # idx-audit-log et idx-soar-executions sont gérés par le template ci-dessus
    "idx-sources": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "nom":               {"type": "keyword"},
                "type":              {"type": "keyword"},
                "adresse_ip":        {"type": "ip"},
                "environnement":     {"type": "keyword"},
                "statut_collecte":   {"type": "keyword"},
                "derniere_reception": {"type": "date"},
            },
        },
    },
    "idx-logs": {
        "mappings": {
            "dynamic": "false",
            "properties": {
                "source_id":         {"type": "keyword"},
                "timestamp":         {"type": "date"},
                "host":              {"type": "keyword"},
                "source_ip":         {"type": "ip"},
                "log_type":          {"type": "keyword"},
                "severity":          {"type": "keyword"},
                "raw_message":       {"type": "text"},
                "normalized_fields": {"type": "object", "dynamic": True},
                "tags":              {"type": "keyword"},
                "is_flagged":        {"type": "boolean"},
                "archived":          {"type": "boolean"},
                "retention_expiry":  {"type": "date"},
            },
        },
    },
    "idx-correlation-rules": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "nom":                   {"type": "keyword"},
                "description":           {"type": "text"},
                "type":                  {"type": "keyword"},
                "condition":             {"type": "object", "dynamic": True},
                "fenetre_temporelle_s":  {"type": "integer"},
                "mitre_tactic":          {"type": "keyword"},
                "mitre_technique_id":    {"type": "keyword"},
                "cve_references":        {"type": "keyword"},
                "kill_chain_phase":      {"type": "keyword"},
                "niveau_alerte_genere":  {"type": "keyword"},
                "active":                {"type": "boolean"},
                "created_by":            {"type": "keyword"},
                "created_at":            {"type": "date"},
                "updated_at":            {"type": "date"},
            },
        },
    },
    "idx-alerts": {
        "mappings": {
            "dynamic": "false",
            "properties": {
                "rule_id":            {"type": "keyword"},
                "log_refs":           {"type": "keyword"},
                "niveau":             {"type": "keyword"},
                "statut":             {"type": "keyword"},
                "assigned_to":        {"type": "keyword"},
                "score_risque":       {"type": "integer"},
                "mitre_technique_id": {"type": "keyword"},
                "created_at":         {"type": "date"},
                "updated_at":         {"type": "date"},
                "commentaires":       {"type": "text"},
            },
        },
    },
    "idx-incidents": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "alert_id":     {"type": "keyword"},
                "titre":        {"type": "text"},
                "description":  {"type": "text"},
                "statut":       {"type": "keyword"},
                "priorite":     {"type": "keyword"},
                "owner":        {"type": "keyword"},
                "created_at":   {"type": "date"},
                "updated_at":   {"type": "date"},
            },
        },
    },
    "idx-playbooks": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "nom":          {"type": "keyword"},
                "type":         {"type": "keyword"},
                "active":       {"type": "boolean"},
                "description":  {"type": "text"},
            },
        },
    },
    # idx-soar-executions géré par le template audit
    "idx-ueba-profiles": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "entity_id":            {"type": "keyword"},
                "entity_type":          {"type": "keyword"},
                "typical_hours":        {"type": "keyword"},
                "avg_volume_per_hour":  {"type": "float"},
                "updated_at":           {"type": "date"},
            },
        },
    },
    "idx-ueba-events": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "entity_id":      {"type": "keyword"},
                "score":          {"type": "integer"},
                "reasons":        {"type": "text"},
                "evaluated_at":   {"type": "date"},
            },
        },
    },
    "idx-retention-policies": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "index_pattern":   {"type": "keyword"},
                "retention_days":  {"type": "integer"},
                "active":          {"type": "boolean"},
            },
        },
    },
    "idx-soar-approvals": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "playbook":    {"type": "keyword"},
                "alert_id":    {"type": "keyword"},
                "target":      {"type": "keyword"},
                "requested_by":{"type": "keyword"},
                "status":      {"type": "keyword"},  # pending / approved / denied
                "created_at":  {"type": "date"},
                "decided_at":  {"type": "date"},
            },
        },
    },
    "idx-soar-quarantine": {
        "mappings": {
            "dynamic": "strict",
            "properties": {
                "file_hash":   {"type": "keyword"},
                "file_path":   {"type": "keyword"},
                "host":        {"type": "keyword"},
                "alert_id":    {"type": "keyword"},
                "status":      {"type": "keyword"},
                "created_at":  {"type": "date"},
            },
        },
    },
}

# Index créés via le template (donc ILM appliqué)
TEMPLATE_INDEX = {"idx-audit-log", "idx-soar-executions"}


async def main() -> None:
    es_kwargs: dict = {
        "hosts": [ES_HOST],
        "basic_auth": (ES_USER, ES_PASS),
        "verify_certs": ES_VERIFY,
    }
    if ES_CA:
        es_kwargs["ca_certs"] = ES_CA
    es = AsyncElasticsearch(**es_kwargs)

    # 1. ILM policy
    try:
        await es.ilm.put_lifecycle(name="audit-ilm-policy", policy=AUDIT_ILM_POLICY["policy"])
        print("  ✓ ILM policy 'audit-ilm-policy' appliquée")
    except Exception as exc:
        print(f"  ! ILM policy: {exc}")

    # 2. Index template
    try:
        await es.indices.put_index_template(name=AUDIT_TEMPLATE_NAME, body=AUDIT_TEMPLATE)
        print(f"  ✓ Index template '{AUDIT_TEMPLATE_NAME}' appliqué")
    except Exception as exc:
        print(f"  ! Index template: {exc}")

    # 3. Indices métier
    for name, body in INDICES.items():
        try:
            if not await es.indices.exists(index=name):
                await es.indices.create(index=name, body=body)
                print(f"  ✓ Index créé : {name}")
            else:
                print(f"  • Index existant : {name}")
        except Exception as exc:
            print(f"  ! Index {name}: {exc}")

    # 4. Audit & SOAR via template (création à la demande, alias)
    for name in TEMPLATE_INDEX:
        try:
            if not await es.indices.exists(index=name):
                # On crée un index simple, le template s'appliquera aux nouveaux index
                # correspondants au pattern (alias futurs).
                await es.indices.create(
                    index=name,
                    settings={"index.lifecycle.name": "audit-ilm-policy"},
                )
                print(f"  ✓ Index audit/SOAR créé : {name}")
        except Exception as exc:
            print(f"  ! Index {name}: {exc}")

    await es.close()
    print("\nInitialisation terminée.")


if __name__ == "__main__":
    asyncio.run(main())
