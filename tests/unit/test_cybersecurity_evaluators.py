"""
tests/unit/test_cybersecurity_evaluators.py — Tests unitaires pour les évaluateurs et l'UEBA

Responsable : Ingénieur QA / Sécurité
"""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from correlation.evaluators.statistical import StatisticalEvaluator
from correlation.evaluators.cross_source import CrossSourceEvaluator
from correlation.ueba.profiler import compute_profile
from correlation.ueba.anomaly_detector import detect_anomaly
from correlation.ueba.risk_scorer import compute_risk_score
from soar.notifiers.tls_config import get_smtp_ssl_context, get_http_ssl_context


@pytest.mark.asyncio
async def test_statistical_evaluator_anomaly_detected():
    """Vérifie que l'évaluateur statistique détecte une anomalie Z-score."""
    mock_es = AsyncMock()
    
    # Mock de la valeur courante (ex: 50 événements dans la fenêtre d'évaluation)
    mock_es.search.side_effect = [
        # Premier appel : logs courants
        {
            "hits": {
                "total": {"value": 50},
                "hits": [{"_id": "log1", "_source": {}}]
            }
        },
        # Deuxième appel : baseline historique avec 5 buckets stables (ex: moyenne 5, stddev proche de 0)
        {
            "aggregations": {
                "history_buckets": {
                    "buckets": [
                        {"doc_count": 5},
                        {"doc_count": 5},
                        {"doc_count": 5},
                        {"doc_count": 5},
                        {"doc_count": 5},
                    ]
                }
            }
        }
    ]

    rule = {
        "id": "test_stat",
        "type": "statistical",
        "condition": {
            "z_score_threshold": 3.0,
            "min_events": 5,
            "baseline_window_s": 86400,
            "bucket_interval_s": 3600
        },
        "fenetre_temporelle_s": 300
    }

    evaluator = StatisticalEvaluator(mock_es)
    matched, ids = await evaluator.evaluate(rule)

    assert matched is True
    assert ids == ["log1"]


@pytest.mark.asyncio
async def test_statistical_evaluator_no_anomaly():
    """Vérifie que l'évaluateur statistique ne déclenche pas si le Z-score est faible."""
    mock_es = AsyncMock()
    
    # Mock de la valeur courante et historique similaires (ex: courant 5, moyenne 5)
    mock_es.search.side_effect = [
        # Courant
        {
            "hits": {
                "total": {"value": 5},
                "hits": [{"_id": "log1", "_source": {}}]
            }
        },
        # Historique
        {
            "aggregations": {
                "history_buckets": {
                    "buckets": [
                        {"doc_count": 5},
                        {"doc_count": 5},
                        {"doc_count": 5},
                        {"doc_count": 5},
                        {"doc_count": 5},
                    ]
                }
            }
        }
    ]

    rule = {
        "id": "test_stat",
        "type": "statistical",
        "condition": {
            "z_score_threshold": 3.0,
            "min_events": 2,
            "baseline_window_s": 86400,
            "bucket_interval_s": 3600
        },
        "fenetre_temporelle_s": 300
    }

    evaluator = StatisticalEvaluator(mock_es)
    matched, ids = await evaluator.evaluate(rule)

    assert matched is False
    assert ids == []


@pytest.mark.asyncio
async def test_cross_source_evaluator_matched():
    """Vérifie que l'évaluateur cross-source détecte un événement inter-sources."""
    mock_es = AsyncMock()
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {"_id": "log1", "_source": {"normalized_fields": {"username": "huber"}, "source_id": "firewall"}},
                {"_id": "log2", "_source": {"normalized_fields": {"username": "huber"}, "source_id": "active_directory"}},
            ]
        }
    }

    rule = {
        "id": "test_cross",
        "type": "cross_source",
        "condition": {
            "entity_field": "normalized_fields.username",
            "min_sources": 2,
            "steps": [
                {"field": "source_id", "value": "firewall"},
                {"field": "source_id", "value": "active_directory"}
            ]
        },
        "fenetre_temporelle_s": 300
    }

    evaluator = CrossSourceEvaluator(mock_es)
    matched, ids = await evaluator.evaluate(rule)

    assert matched is True
    assert len(ids) == 2


@pytest.mark.asyncio
async def test_ueba_profiler_and_anomaly_detection():
    """Teste le cycle de création de profil et de détection d'anomalies UEBA."""
    mock_es = AsyncMock()

    # Mock pour compute_profile : historique avec des IPs et hôtes connus
    mock_es.search.return_value = {
        "aggregations": {
            "hourly": {"buckets": [{"key_as_string": "2026-06-25T10:00:00", "doc_count": 10}]},
            "source_ips": {"buckets": [{"key": "192.168.1.50"}]},
            "hosts": {"buckets": [{"key": "workstation-01"}]},
            "countries": {"buckets": [{"key": "FR"}]},
            "user_agents": {"buckets": [{"key": "Mozilla/5.0"}]},
        }
    }

    # 1. Calcul du profil
    profile = await compute_profile(mock_es, "huber", "user")
    assert profile["entity_id"] == "huber"
    assert "FR" in profile["known_countries"]
    assert "Mozilla/5.0" in profile["known_user_agents"]

    # Mock pour detect_anomaly : retourner le profil créé
    mock_es.get.return_value = {"_source": profile}

    # 2. Détection d'anomalie : connexion depuis un pays étranger (US) et appareil inconnu
    anomaly = await detect_anomaly(
        mock_es,
        entity_id="huber",
        current_hour="03",  # Hors horaires (profil typique a uniquement 10h)
        current_volume=5,
        source_ip="8.8.8.8",
        host="server-critical",
        geo_country="US",
        user_agent="EvilScraper/1.0"
    )

    assert anomaly["score"] > 0
    assert any("horaires habituels" in r for r in anomaly["reasons"])
    assert any("Pays de connexion" in r for r in anomaly["reasons"])
    assert any("User Agent" in r for r in anomaly["reasons"])


@pytest.mark.asyncio
async def test_ueba_risk_scorer_decay():
    """Vérifie le calcul du score de risque UEBA avec decay temporel."""
    mock_es = AsyncMock()

    # Mock de la dernière alerte de risque UEBA indexée il y a 2 heures avec score 80
    mock_es.search.return_value = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "score_risque": 80,
                        "created_at": "2026-06-25T20:00:00Z",  # Local time is 22:00 in the test
                        "rule_id": "ueba-detection"
                    }
                }
            ]
        }
    }

    anomaly_result = {
        "score": 30,
        "reasons": ["IP inconnue"],
        "source_ip": "10.0.0.1",
        "host": "host-01"
    }

    # Appel du calcul du score
    # Score initial = 80. Après 2h avec 5% decay/h -> 80 * exp(-0.05 * 2) = 72.38.
    # Score combiné = max(30 + 72/2, 72) = max(66, 72) = 72.
    combined = await compute_risk_score(mock_es, "huber", anomaly_result)
    assert combined >= 70
    mock_es.index.assert_called_once()  # Une alerte de niveau HIGH/CRITICAL doit être créée


def test_tls_config_contexts():
    """Vérifie la création des contextes SSL pour SMTP et HTTP."""
    smtp_ctx = get_smtp_ssl_context()
    assert smtp_ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    with patch("soar.notifiers.tls_config.build_ssl_context") as mock_build:
        mock_build.return_value = ssl.create_default_context()
        http_ctx = get_http_ssl_context(verify=True)
        assert http_ctx is not None
        mock_build.assert_called_once_with(verify=True)
