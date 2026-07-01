from __future__ import annotations

from app.correlation_rules.models import CorrelationRule


async def list_rules() -> list[CorrelationRule]:
    # Données figées de démo. La vraie source (Elasticsearch, avec pagination et
    # création/suppression) est api/v1/rules/service.py.
    return [
        CorrelationRule(id="rule-1", name="Brute force SSH", description="Detects SSH brute force", enabled=True),
        CorrelationRule(id="rule-2", name="Suspicious PowerShell", description="Detects suspicious PowerShell", enabled=False),
    ]


async def toggle_rule(rule_id: str, enabled: bool) -> CorrelationRule:
    # NOTE : ne persiste rien nulle part — renvoie simplement un objet reflétant
    # le changement demandé (comportement de démo, pas de vraie base de données).
    return CorrelationRule(id=rule_id, name="Updated rule", enabled=enabled)
