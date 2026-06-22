"""
scripts/init_elasticsearch.py — Création des 13 index ES au démarrage
"""
import asyncio, json, os
from elasticsearch import AsyncElasticsearch

ES_HOST = os.getenv("ELASTICSEARCH_HOST","http://elasticsearch:9200")
ES_USER = os.getenv("ELASTICSEARCH_USERNAME","elastic")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD","changeme")

INDICES = {
    "idx-users":              {"mappings":{"properties":{"username":{"type":"keyword"},"password_hash":{"type":"keyword","index":False},"email":{"type":"keyword"},"role_id":{"type":"keyword"},"org_scope":{"type":"keyword"},"is_active":{"type":"boolean"},"created_at":{"type":"date"},"last_login_at":{"type":"date"}}}},
    "idx-roles":              {"mappings":{"properties":{"nom":{"type":"keyword"},"permissions":{"type":"object"},"description":{"type":"text"}}}},
    "idx-audit-log":          {"mappings":{"properties":{"user_id":{"type":"keyword"},"action":{"type":"keyword"},"target_entity":{"type":"keyword"},"target_id":{"type":"keyword"},"ip_address":{"type":"ip"},"details":{"type":"object"},"created_at":{"type":"date"}}}},
    "idx-sources":            {"mappings":{"properties":{"nom":{"type":"keyword"},"type":{"type":"keyword"},"adresse_ip":{"type":"ip"},"environnement":{"type":"keyword"},"statut_collecte":{"type":"keyword"},"derniere_reception":{"type":"date"}}}},
    "idx-logs":               {"mappings":{"properties":{"source_id":{"type":"keyword"},"timestamp":{"type":"date"},"host":{"type":"keyword"},"source_ip":{"type":"ip"},"log_type":{"type":"keyword"},"severity":{"type":"keyword"},"raw_message":{"type":"text"},"normalized_fields":{"type":"object"},"tags":{"type":"keyword"},"is_flagged":{"type":"boolean"},"archived":{"type":"boolean"},"retention_expiry":{"type":"date"}}}},
    "idx-correlation-rules":  {"mappings":{"properties":{"nom":{"type":"keyword"},"type":{"type":"keyword"},"condition":{"type":"object"},"fenetre_temporelle_s":{"type":"integer"},"mitre_tactic":{"type":"keyword"},"niveau_alerte_genere":{"type":"keyword"},"active":{"type":"boolean"},"created_by":{"type":"keyword"}}}},
    "idx-alerts":             {"mappings":{"properties":{"rule_id":{"type":"keyword"},"log_refs":{"type":"keyword"},"niveau":{"type":"keyword"},"statut":{"type":"keyword"},"assigned_to":{"type":"keyword"},"score_risque":{"type":"integer"},"created_at":{"type":"date"},"updated_at":{"type":"date"},"commentaires":{"type":"text"}}}},
    "idx-incidents":          {"mappings":{"properties":{"alert_id":{"type":"keyword"},"titre":{"type":"text"},"description":{"type":"text"},"statut":{"type":"keyword"},"priorite":{"type":"keyword"},"owner":{"type":"keyword"},"created_at":{"type":"date"},"updated_at":{"type":"date"}}}},
    "idx-playbooks":          {"mappings":{"properties":{"nom":{"type":"keyword"},"type":{"type":"keyword"},"active":{"type":"boolean"}}}},
    "idx-soar-executions":    {"mappings":{"properties":{"playbook_id":{"type":"keyword"},"alert_id":{"type":"keyword"},"status":{"type":"keyword"},"result":{"type":"object"},"executed_at":{"type":"date"}}}},
    "idx-ueba-profiles":      {"mappings":{"properties":{"entity_id":{"type":"keyword"},"entity_type":{"type":"keyword"},"typical_hours":{"type":"keyword"},"avg_volume_per_hour":{"type":"float"},"updated_at":{"type":"date"}}}},
    "idx-ueba-events":        {"mappings":{"properties":{"entity_id":{"type":"keyword"},"score":{"type":"integer"},"reasons":{"type":"text"},"evaluated_at":{"type":"date"}}}},
    "idx-retention-policies": {"mappings":{"properties":{"index_pattern":{"type":"keyword"},"retention_days":{"type":"integer"},"active":{"type":"boolean"}}}},
}

async def main():
    es = AsyncElasticsearch(hosts=[ES_HOST],basic_auth=(ES_USER,ES_PASS),verify_certs=False)
    for name, body in INDICES.items():
        if not await es.indices.exists(index=name):
            await es.indices.create(index=name,body=body)
            print(f"  ? Index créé : {name}")
        else:
            print(f"  ?  Index existant : {name}")
    await es.close(); print("\nInitialisation terminée.")

if __name__ == "__main__":
    asyncio.run(main())
