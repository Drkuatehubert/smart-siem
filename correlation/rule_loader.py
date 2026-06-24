"""
rule_loader.py — Chargement et validation des règles de corrélation

Responsable : Ingénieur Data
Exigences : RF-COR-01 (seuil), RF-COR-02 (séquentiel), RBAC admin (rules:manage)

Ce module :
  * charge toutes les règles actives depuis `idx-correlation-rules` ;
  * valide chaque règle via `RuleSchema` (Pydantic) à l'import ;
  * lève / log explicitement en cas de règle invalide (jamais silent drop) ;
  * expose un chargeur YAML sur disque pour `seed_rules.py`.
"""

from __future__ import annotations

import glob
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("correlation.rule_loader")


# ─────────────────────────────────────────────────────────────────────
# Schéma de validation
# ─────────────────────────────────────────────────────────────────────

VALID_LEVELS = {"INFO", "WARNING", "HIGH", "CRITICAL"}
KILL_CHAIN_PHASES = {
    "recon", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "exfiltration",
    "impact", "c2",
}
MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class RuleCondition(BaseModel):
    """Sous-structure d'une règle (seuil ou séquentiel)."""
    field: Optional[str] = None
    value: Optional[Any] = None
    threshold: Optional[int] = Field(default=None, ge=1, le=100_000)
    steps: Optional[List[Dict[str, Any]]] = None

    @field_validator("steps")
    @classmethod
    def _steps_non_empty(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError("steps ne peut pas être vide")
        return v


class RuleSchema(BaseModel):
    """Schéma strict d'une règle de corrélation (durée MITRE)."""
    id: str = Field(..., min_length=3, max_length=128)
    nom: str = Field(..., min_length=3, max_length=256)
    description: str = Field(..., max_length=2048)
    type: str = Field(..., pattern=r"^(seuil|sequentielle)$")
    condition: RuleCondition
    fenetre_temporelle_s: int = Field(..., ge=1, le=86400 * 7)
    mitre_tactic: str = Field(..., min_length=1, max_length=128)
    mitre_technique_id: str
    niveau_alerte_genere: str
    cve_references: List[str] = Field(default_factory=list)
    kill_chain_phase: Optional[str] = None
    active: bool = True

    @field_validator("niveau_alerte_genere")
    @classmethod
    def _niveau_valide(cls, v: str) -> str:
        if v not in VALID_LEVELS:
            raise ValueError(f"niveau_alerte_genere invalide : {v}")
        return v

    @field_validator("mitre_technique_id")
    @classmethod
    def _mitre_valide(cls, v: str) -> str:
        if not MITRE_TECHNIQUE_RE.match(v):
            raise ValueError(f"mitre_technique_id doit matcher {MITRE_TECHNIQUE_RE.pattern} : {v}")
        return v

    @field_validator("kill_chain_phase")
    @classmethod
    def _phase_valide(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in KILL_CHAIN_PHASES:
            raise ValueError(f"kill_chain_phase invalide : {v}")
        return v


# ─────────────────────────────────────────────────────────────────────
# Chargement depuis Elasticsearch
# ─────────────────────────────────────────────────────────────────────

async def load_rules(es) -> List[Dict[str, Any]]:
    """
    Charge les règles actives depuis `idx-correlation-rules`.
    Valide chacune via `RuleSchema` ; les règles invalides sont logguées
    (en WARNING) puis exclues.
    """
    try:
        res = await es.search(
            index="idx-correlation-rules",
            query={"term": {"active": True}},
            size=500,
        )
    except Exception as exc:
        logger.error("Chargement des règles impossible : %s", exc)
        return []

    validated: List[Dict[str, Any]] = []
    for hit in res["hits"]["hits"]:
        doc = {"id": hit["_id"], **hit["_source"]}
        try:
            RuleSchema.model_validate(doc)
            validated.append(doc)
        except Exception as exc:
            logger.warning(
                "Règle invalide exclue (id=%s) : %s", hit["_id"], exc,
            )
    return validated


# ─────────────────────────────────────────────────────────────────────
# Chargement YAML (pour seed et tests)
# ─────────────────────────────────────────────────────────────────────

def load_rule_file(path: str | os.PathLike) -> Dict[str, Any]:
    """
    Charge un YAML, valide, et renvoie le dict prêt à être indexé.
    Lève si invalide.
    """
    with open(path, "r", encoding="utf-8") as fp:
        raw = yaml.safe_load(fp)
    return RuleSchema.model_validate(raw).model_dump()


def load_rule_dir(directory: str | os.PathLike) -> List[Dict[str, Any]]:
    """Charge tous les .yaml d'un dossier et les valide."""
    out: List[Dict[str, Any]] = []
    for p in sorted(glob.glob(str(Path(directory) / "*.yaml"))):
        try:
            out.append(load_rule_file(p))
        except Exception as exc:
            logger.error("Règle %s invalide : %s", p, exc)
            raise
    return out
