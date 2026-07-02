#!/usr/bin/env python3
"""
correlation_engine/seed_rules.py — Charge les règles YAML (./rules) dans PostgreSQL.

Adapté de Data/load_yaml_rule.py (script original de seed v2). Idempotent :
une règle déjà présente (par nom) est ignorée, donc ce script peut être
relancé sans risque à chaque démarrage du conteneur correlation-engine.

Nécessite un utilisateur admin existant dans la table `users` (colonne
created_by de correlation_rules) : voir correlation_engine/db/02_bootstrap_admin.sql.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Optional

import asyncpg
import yaml

from .config import PG_DSN

RULES_DIR = str(Path(__file__).resolve().parent / "rules")

SEP = "─" * 70

FOLDER_TO_TACTIC = {
    "reconnaissance":       "TA0043",
    "initial_access":       "TA0001",
    "execution":            "TA0002",
    "persistence":          "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion":      "TA0005",
    "credential_access":    "TA0006",
    "discovery":            "TA0007",
    "lateral_movement":     "TA0008",
    "collection":           "TA0009",
    "command_control":      "TA0011",
    "exfiltration":         "TA0010",
    "impact":               "TA0040",
}

TECHNIQUE_TO_TACTIC = {
    "T1595": "TA0043", "T1592": "TA0043", "T1590": "TA0043", "T1046": "TA0007",
    "T1190": "TA0001", "T1078": "TA0001", "T1110": "TA0001", "T1566": "TA0001", "T1133": "TA0001",
    "T1059": "TA0002", "T1047": "TA0002", "T1053": "TA0002",
    "T1098": "TA0003", "T1543": "TA0003", "T1546": "TA0003",
    "T1548": "TA0004", "T1068": "TA0004", "T1055": "TA0004",
    "T1070": "TA0005", "T1036": "TA0005", "T1562": "TA0005", "T1112": "TA0005",
    "T1003": "TA0006", "T1555": "TA0006", "T1558": "TA0006", "T1552": "TA0006", "T1557": "TA0006",
    "T1087": "TA0007", "T1083": "TA0007", "T1018": "TA0007", "T1082": "TA0007",
    "T1049": "TA0007", "T1135": "TA0007",
    "T1021": "TA0008", "T1534": "TA0008", "T1550": "TA0008", "T1080": "TA0008", "T1210": "TA0008",
    "T1020": "TA0010", "T1030": "TA0010", "T1041": "TA0010", "T1048": "TA0010",
    "T1567": "TA0010", "T1029": "TA0010", "T1095": "TA0010",
    "T1485": "TA0040", "T1486": "TA0040", "T1490": "TA0040", "T1499": "TA0040",
}

ALERT_LEVEL_MAP = {
    "critical": "CRITICAL", "high": "HIGH",
    "medium": "WARNING", "warning": "WARNING",
    "low": "INFO", "info": "INFO",
}

RULE_TYPE_MAP = {
    "seuil": "threshold", "séquence": "pattern", "sequence": "pattern",
    "comportemental": "behavioral", "composite": "composite",
    "threshold": "threshold", "pattern": "pattern",
    "behavioral": "behavioral", "count": "threshold", "frequency": "threshold",
}

MSG_TO_ACTION = {
    "Failed password": "ssh_auth_failure",
    "authentication failure": "ssh_auth_failure",
    "Invalid user": "ssh_auth_failure",
    "Accepted password": "ssh_auth_success",
    "Accepted publickey": "ssh_auth_success",
}


def extract_technique_id(mitre_str: Optional[str]) -> Optional[str]:
    if not mitre_str:
        return None
    match = re.search(r"(T\d{4})(?:\.\d{3})?", str(mitre_str))
    return match.group(1) if match else None


def resolve_tactic(yaml_rule: dict, folder_name: str) -> Optional[str]:
    mitre_raw = yaml_rule.get("mitre_tactic", "")
    ta_match = re.search(r"TA\d{4}", str(mitre_raw))
    if ta_match:
        return ta_match.group(0)

    tech_id = extract_technique_id(
        yaml_rule.get("mitre_technique_id") or yaml_rule.get("mitre_tactic")
    )
    if tech_id and tech_id in TECHNIQUE_TO_TACTIC:
        return TECHNIQUE_TO_TACTIC[tech_id]

    folder_lower = folder_name.lower().replace("-", "_").replace(" ", "_")
    return FOLDER_TO_TACTIC.get(folder_lower)


def build_conditions(yaml_rule: dict) -> dict:
    condition = yaml_rule.get("condition", {})
    rule_type = RULE_TYPE_MAP.get(str(yaml_rule.get("type", "threshold")).lower(), "threshold")
    group_by = condition.get("group_by") or "source_ip"

    if rule_type == "threshold":
        event_action = condition.get("event_action")
        if not event_action:
            value = condition.get("value", "")
            field = condition.get("field", "")
            event_action = MSG_TO_ACTION.get(value) or MSG_TO_ACTION.get(field) or value
        conditions = {"event_action": event_action, "group_by": group_by}
        if condition.get("count_type"):
            conditions["count_type"] = condition["count_type"]
        if condition.get("cardinality_field"):
            conditions["cardinality_field"] = condition["cardinality_field"]
        return conditions

    if rule_type == "pattern":
        return {"sequence": condition.get("sequence", []), "group_by": group_by}

    if rule_type == "composite":
        return {
            "type": "cross_source",
            "sources": condition.get("sources", []),
            "events": condition.get("events", {}),
            "group_by": group_by,
        }

    return {"group_by": group_by}


async def load_rules_from_directory(pool: asyncpg.Pool, rules_dir: str) -> None:
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        print(f"[ERREUR] Dossier introuvable : {rules_dir}")
        return

    async with pool.acquire() as conn:
        admin_id = await conn.fetchval("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    if not admin_id:
        print("[ERREUR] Aucun admin trouvé — appliquer db/02_bootstrap_admin.sql d'abord")
        return

    yaml_files = sorted(list(rules_path.rglob("*.yaml")) + list(rules_path.rglob("*.yml")))
    print(f"\n[SCAN] {len(yaml_files)} fichiers YAML dans {rules_dir}")
    print(SEP)

    stats = {"total": 0, "inserted": 0, "skipped": 0, "inactive": 0, "errors": 0}

    for yaml_file in yaml_files:
        stats["total"] += 1
        folder_name = yaml_file.parent.name

        try:
            with open(yaml_file, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            if not rule:
                continue
            if not rule.get("active", True):
                stats["inactive"] += 1
                continue

            name = rule.get("nom") or rule.get("name") or yaml_file.stem
            tech_id = extract_technique_id(rule.get("mitre_technique_id") or rule.get("mitre_tactic"))
            tactic_id = resolve_tactic(rule, folder_name)
            alert_level = ALERT_LEVEL_MAP.get(str(rule.get("niveau_alerte_genere", "WARNING")).lower(), "WARNING")
            rule_type = RULE_TYPE_MAP.get(str(rule.get("type", "threshold")).lower(), "threshold")
            window_sec = int(rule.get("fenetre_temporelle_s") or rule.get("time_window_seconds") or 60)
            conf_score = int(rule.get("confidence_score", 70))
            conditions = build_conditions(rule)
            threshold_cnt = None
            if rule_type == "threshold":
                threshold_cnt = int(
                    rule.get("condition", {}).get("threshold") or rule.get("threshold_count") or 5
                )

            async with pool.acquire() as conn:
                exists = await conn.fetchval("SELECT id FROM correlation_rules WHERE name = $1", name)
            if exists:
                stats["skipped"] += 1
                continue

            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO correlation_rules (
                        name, description, rule_type, conditions,
                        time_window_seconds, threshold_count,
                        sources_required, alert_level, confidence_score,
                        mitre_tactic, mitre_technique,
                        is_active, created_by
                    ) VALUES (
                        $1, $2, $3, $4::jsonb,
                        $5, $6,
                        $7::jsonb, $8::alert_level, $9,
                        $10, $11,
                        TRUE, $12::uuid
                    )
                    """,
                    name,
                    rule.get("description", ""),
                    rule_type,
                    json.dumps(conditions),
                    window_sec,
                    threshold_cnt,
                    None,
                    alert_level,
                    conf_score,
                    tactic_id,
                    tech_id,
                    str(admin_id),
                )
            print(f"  [OK]  {alert_level:<8} {yaml_file.name}")
            stats["inserted"] += 1

        except yaml.YAMLError as e:
            print(f"  [ERR YAML] {yaml_file.name} : {e}")
            stats["errors"] += 1
        except Exception as e:
            print(f"  [ERR PG]   {yaml_file.name} : {e}")
            stats["errors"] += 1

    print(SEP)
    print(
        f"[RÉSULTAT] total={stats['total']} inserted={stats['inserted']} "
        f"skipped={stats['skipped']} inactive={stats['inactive']} errors={stats['errors']}"
    )


async def main() -> None:
    pool = await asyncpg.create_pool(dsn=PG_DSN, min_size=1, max_size=5)
    try:
        await load_rules_from_directory(pool, RULES_DIR)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
