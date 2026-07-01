"""
reports/services.py

Génère un rapport PDF complet en agrégeant :
  - alerts (PostgreSQL) → top alertes, criticités
  - ueba_profiles (PostgreSQL) → profils à risque
  - siem-logs-* (Elasticsearch) → volume, MITRE tactics, IPs suspectes
  - audit_logs (PostgreSQL) → actions utilisateurs de la période
"""
from datetime import datetime
from uuid import uuid4
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from app.core.database import get_pool
from app.core.elasticsearch import get_es_client, ES_INDEX_PATTERN
from app.reports.models import ReportGenerateRequest, ReportStatus
from app.config import settings


TEMPLATE_DIR = Path(__file__).parent / "templates"
jinja_env    = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))


async def generate_report(req: ReportGenerateRequest) -> dict:
    """
    Pipeline de génération complète.
    1. Collecte les données depuis PostgreSQL et ES
    2. Construit le contexte pour le template HTML
    3. Génère le PDF via WeasyPrint
    4. Stocke les métadonnées dans PostgreSQL
    """
    report_id = uuid4()
    pool      = await get_pool()

    # ── 1. Données alertes ────────────────────────────────────
    async with pool.acquire() as conn:
        alert_stats = await conn.fetchrow(
            """
            SELECT
                COUNT(*) FILTER (WHERE level = 'CRITICAL') AS critical_count,
                COUNT(*) FILTER (WHERE level = 'HIGH')     AS high_count,
                COUNT(*) FILTER (WHERE level = 'WARNING')  AS warning_count,
                COUNT(*) FILTER (WHERE status = 'resolved') AS resolved_count,
                COUNT(*) FILTER (WHERE is_false_positive)  AS false_positive_count,
                COUNT(*)                                   AS total_count
            FROM alerts
            WHERE triggered_at BETWEEN $1 AND $2
            """,
            req.start_date, req.end_date
        )

        top_alerts = await conn.fetch(
            """
            SELECT title, level, mitre_tactic, COUNT(*) AS occurrences
            FROM alerts
            WHERE triggered_at BETWEEN $1 AND $2
            GROUP BY title, level, mitre_tactic
            ORDER BY occurrences DESC LIMIT 10
            """,
            req.start_date, req.end_date
        )

        risky_profiles = await conn.fetch(
            """
            SELECT entity_name, entity_type, risk_score, anomaly_count
            FROM ueba_profiles
            WHERE risk_score >= 70
            ORDER BY risk_score DESC LIMIT 20
            """
        )

    # ── 2. Données Elasticsearch ───────────────────────────────
    es = get_es_client()

    # Top IPs suspectes
    ip_agg = await es.search(
        index=ES_INDEX_PATTERN,
        query={"range": {"@timestamp": {
            "gte": req.start_date.isoformat(),
            "lte": req.end_date.isoformat()
        }}},
        aggs={"top_source_ips": {"terms": {"field": "source_ip", "size": 10}}},
        size=0
    )
    top_ips = ip_agg["aggregations"]["top_source_ips"]["buckets"]

    # Volume par jour
    vol_agg = await es.search(
        index=ES_INDEX_PATTERN,
        query={"range": {"@timestamp": {
            "gte": req.start_date.isoformat(),
            "lte": req.end_date.isoformat()
        }}},
        aggs={"logs_per_day": {"date_histogram": {
            "field": "@timestamp", "calendar_interval": "day"
        }}},
        size=0
    )
    volume_per_day = vol_agg["aggregations"]["logs_per_day"]["buckets"]

    # ── 3. Génération PDF ─────────────────────────────────────
    context = {
        "report_id":      str(report_id),
        "generated_at":   datetime.utcnow().isoformat(),
        "period_start":   req.start_date.isoformat(),
        "period_end":     req.end_date.isoformat(),
        "alert_stats":    dict(alert_stats),
        "top_alerts":     [dict(r) for r in top_alerts],
        "risky_profiles": [dict(r) for r in risky_profiles],
        "top_ips":        top_ips,
        "volume_per_day": volume_per_day,
    }

    template  = jinja_env.get_template("report_template.html")
    html_str  = template.render(**context)
    pdf_bytes = HTML(string=html_str).write_pdf()

    # Sauvegarde du fichier
    output_path = Path(settings.REPORTS_DIR) / f"{report_id}.pdf"
    output_path.write_bytes(pdf_bytes)

    # ── 4. Métadonnées en PostgreSQL ──────────────────────────
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO reports
                (id, report_type, start_date, end_date, file_path,
                 status, triggered_by, generated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            report_id, req.report_type.value,
            req.start_date, req.end_date,
            str(output_path),
            ReportStatus.COMPLETED.value,
            req.triggered_by,
            datetime.utcnow()
        )

    return {"report_id": str(report_id), "file_path": str(output_path)}