from __future__ import annotations

import io
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from typing import Any, List

from app.api.v1.reports.schemas import ReportRequest, ReportOut
from app.core.rbac import require_permission, require_any_role
from app.core.security import get_current_user

logger = logging.getLogger("reports.router")

router = APIRouter(prefix="/reports", tags=["Rapports"])


@router.get("", response_model=List[dict[str, Any]])
async def list_reports(_=Depends(require_any_role)):
    return []


@router.post("/generate", response_model=ReportOut, status_code=202)
async def generate(body: ReportRequest, _=Depends(require_permission("reports:generate"))):
    # 202 Accepted : la génération réelle n'est pas encore implémentée (voir service.py),
    # on renvoie donc un id de substitution avec le statut "queued" (mis en file d'attente).
    return {"id": "report-placeholder", "status": "queued", "download_url": None}


# ── Collecte des données ─────────────────────────────────────────────────────

async def _collect_report_data() -> dict:
    """Collecte données depuis PostgreSQL et Redis pour le rapport PDF."""
    result: dict = {
        "rules": [],
        "logs": [],
        "agents": [],
        "alert_counts": {"total_open": 0, "critical": 0},
        "log_count": 0,
    }

    # PostgreSQL : règles de corrélation + compteurs d'alertes
    try:
        from app.core.postgres import get_pg_pool
        pool = await get_pg_pool()
        async with pool.acquire() as conn:
            rule_rows = await conn.fetch(
                """SELECT name, mitre_tactic, alert_level, confidence_score, is_active
                   FROM correlation_rules ORDER BY created_at DESC LIMIT 50"""
            )
            result["rules"] = [dict(r) for r in rule_rows]

            total_open = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
            ) or 0
            critical = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE status = 'open' AND UPPER(level) = 'CRITICAL'"
            ) or 0
            result["alert_counts"] = {"total_open": int(total_open), "critical": int(critical)}
    except Exception as exc:
        logger.warning("PG collect échoué (rapport) : %s", exc)

    # Redis : 50 derniers logs + clés agent:*
    try:
        from app.core.redis_client import get_redis_client
        r = get_redis_client()

        raw_logs = await r.lrange("recent_logs", 0, 49)
        for raw in raw_logs:
            try:
                result["logs"].append(json.loads(raw))
            except Exception:
                pass
        result["log_count"] = int(await r.llen("recent_logs") or 0)

        agent_keys = await r.keys("agent:*")
        for key in agent_keys:
            raw_agent = await r.get(key)
            if raw_agent:
                try:
                    result["agents"].append(json.loads(raw_agent))
                except Exception:
                    pass
    except Exception as exc:
        logger.warning("Redis collect échoué (rapport) : %s", exc)

    return result


# ── Génération PDF avec reportlab ────────────────────────────────────────────

def _make_style_cmds(num_rows: int, dark_blue: Any, light_grey: Any, mid_grey: Any) -> list:
    """Commandes TableStyle avec alternance de lignes."""
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), dark_blue),
        ("GRID", (0, 0), (-1, -1), 0.3, mid_grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
    from reportlab.lib.colors import white
    for i in range(1, num_rows):
        bg = light_grey if i % 2 == 1 else white
        cmds.append(("BACKGROUND", (0, i), (-1, i), bg))
    return cmds


def _build_pdf(data: dict, analyst_username: str, period: str) -> bytes:
    """Génère le rapport PDF professionnel (5 pages, format A4)."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.colors import HexColor, white
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable, PageBreak,
    )
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT

    DARK_BLUE  = HexColor("#1e3a5f")
    LIGHT_GREY = HexColor("#f5f5f5")
    MID_GREY   = HexColor("#d0d0d0")
    TEXT_DARK  = HexColor("#1a1a2e")
    TEXT_LIGHT = HexColor("#666666")
    RED_ACCENT = HexColor("#cc2222")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title="Smart SIEM — Rapport de Sécurité",
        author="Smart SIEM v1.0",
    )

    # Styles paragraphes
    def ps(name: str, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    s_white   = ps("sw", fontName="Helvetica", fontSize=9, textColor=white)
    s_wbold   = ps("swb", fontName="Helvetica-Bold", fontSize=9, textColor=white)
    s_body    = ps("sb", fontName="Helvetica", fontSize=8, textColor=TEXT_DARK)
    s_h2      = ps("sh2", fontName="Helvetica-Bold", fontSize=13, textColor=DARK_BLUE, spaceBefore=8, spaceAfter=6)
    s_src     = ps("ssrc", fontName="Helvetica-Oblique", fontSize=8, textColor=TEXT_LIGHT, spaceAfter=8)
    s_meta    = ps("sm", fontName="Helvetica", fontSize=9, textColor=TEXT_LIGHT, spaceAfter=10)

    now_utc = datetime.now(timezone.utc)
    generated_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    critical    = data["alert_counts"]["critical"]
    total_open  = data["alert_counts"]["total_open"]
    active_agents = sum(1 for a in data["agents"] if a.get("status") == "active")
    active_rules  = sum(1 for r in data["rules"] if r.get("is_active"))
    security_score = max(0, min(100, 100 - critical * 10 - max(0, total_open - critical) * 2))

    story: list = []

    # ── PAGE 1 : En-tête & Résumé exécutif ─────────────────────────────────────

    hdr_data = [[
        Paragraph(
            "SMART SIEM",
            ps("hL", fontName="Helvetica-Bold", fontSize=24, textColor=white, alignment=TA_LEFT),
        ),
        Paragraph(
            f"Rapport de Sécurité — Période : {period}<br/>"
            f"<font size='9'>Généré le : {generated_str}</font>",
            ps("hR", fontName="Helvetica", fontSize=11, textColor=white, alignment=TA_RIGHT, leading=16),
        ),
    ]]
    hdr_tbl = Table(hdr_data, colWidths=[9*cm, 8.7*cm])
    hdr_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), DARK_BLUE),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (0, -1),  20),
        ("RIGHTPADDING",  (-1, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
    ]))
    story.append(hdr_tbl)
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        f"Analyste : <b>{analyst_username}</b>&nbsp;&nbsp;|&nbsp;&nbsp;"
        f"Score de risque global : <b>{security_score} / 100</b>",
        s_meta,
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY, spaceAfter=8))
    story.append(Paragraph("RÉSUMÉ EXÉCUTIF", s_h2))

    summary_rows = [
        [Paragraph("Indicateur", s_wbold), Paragraph("Valeur", s_wbold)],
        [Paragraph("Total logs collectés", s_body),
         Paragraph(f"{data['log_count']:,}".replace(",", " "), s_body)],
        [Paragraph("Alertes actives (ouvertes)", s_body), Paragraph(str(total_open), s_body)],
        [Paragraph("Alertes critiques", s_body), Paragraph(str(critical), s_body)],
        [Paragraph("Agents en ligne", s_body),
         Paragraph(f"{active_agents} / {len(data['agents'])}", s_body)],
        [Paragraph("Règles de corrélation actives", s_body), Paragraph(str(active_rules), s_body)],
        [Paragraph("Score de posture sécurité", s_body),
         Paragraph(f"{security_score} / 100", s_body)],
    ]
    sum_cmds = _make_style_cmds(len(summary_rows), DARK_BLUE, LIGHT_GREY, MID_GREY)
    sum_tbl = Table(summary_rows, colWidths=[10*cm, 7.7*cm])
    sum_tbl.setStyle(TableStyle(sum_cmds))
    story.append(sum_tbl)
    story.append(PageBreak())

    # ── PAGE 2 : Règles de corrélation ─────────────────────────────────────────

    story.append(Paragraph("INVENTAIRE DES RÈGLES DE CORRÉLATION", s_h2))
    story.append(Paragraph("Source : PostgreSQL — table correlation_rules", s_src))

    rules_rows = [
        [Paragraph(h, s_wbold) for h in
         ["Nom", "Tactique MITRE", "Sévérité", "Confiance", "Statut"]],
    ]
    for r in data["rules"]:
        rules_rows.append([
            Paragraph(str(r.get("name") or "—")[:45], s_body),
            Paragraph(str(r.get("mitre_tactic") or "—"), s_body),
            Paragraph(str(r.get("alert_level") or "—").upper(), s_body),
            Paragraph(str(r.get("confidence_score") or "—"), s_body),
            Paragraph("Actif" if r.get("is_active") else "Inactif", s_body),
        ])
    if len(rules_rows) == 1:
        rules_rows.append([Paragraph("Aucune règle trouvée", s_body), *[""] * 4])

    rules_tbl = Table(rules_rows, colWidths=[6.5*cm, 4*cm, 2.5*cm, 2.2*cm, 2.5*cm])
    rules_tbl.setStyle(TableStyle(
        _make_style_cmds(len(rules_rows), DARK_BLUE, LIGHT_GREY, MID_GREY)
    ))
    story.append(rules_tbl)
    story.append(PageBreak())

    # ── PAGE 3 : Logs récents ──────────────────────────────────────────────────

    story.append(Paragraph("LOGS RÉCENTS (50 DERNIERS)", s_h2))
    story.append(Paragraph("Source : Redis — liste recent_logs", s_src))

    logs_rows = [
        [Paragraph(h, s_wbold) for h in
         ["Horodatage", "Source IP", "Action", "Sévérité", "Message"]],
    ]
    for log in data["logs"]:
        ts  = str(log.get("@timestamp") or log.get("timestamp") or "—")[:19]
        msg = str(log.get("raw_message") or log.get("message") or "—")[:80]
        logs_rows.append([
            Paragraph(ts, s_body),
            Paragraph(str(log.get("source_ip") or "—"), s_body),
            Paragraph(str(log.get("event_action") or "—")[:25], s_body),
            Paragraph(str(log.get("severity") or "—").upper(), s_body),
            Paragraph(msg, s_body),
        ])
    if len(logs_rows) == 1:
        logs_rows.append([Paragraph("Aucun log disponible", s_body), *[""] * 4])

    logs_tbl = Table(logs_rows, colWidths=[3.5*cm, 3*cm, 3*cm, 2.2*cm, 6*cm])
    logs_style = _make_style_cmds(len(logs_rows), DARK_BLUE, LIGHT_GREY, MID_GREY)
    logs_style.append(("VALIGN", (0, 0), (-1, -1), "TOP"))
    logs_tbl.setStyle(TableStyle(logs_style))
    story.append(logs_tbl)
    story.append(PageBreak())

    # ── PAGE 4 : Agents & Infrastructure ──────────────────────────────────────

    story.append(Paragraph("AGENTS & INFRASTRUCTURE", s_h2))
    story.append(Paragraph("Source : Redis — clés agent:*", s_src))

    agents_rows = [
        [Paragraph(h, s_wbold) for h in
         ["Hôte", "IP", "OS", "Statut", "Dernière activité"]],
    ]
    for agent in data["agents"]:
        status_str = str(agent.get("status") or "inconnu").upper()
        last_seen  = str(agent.get("last_seen") or "—")[:19]
        agents_rows.append([
            Paragraph(str(agent.get("host") or "—"), s_body),
            Paragraph(str(agent.get("ip") or "—"), s_body),
            Paragraph(str(agent.get("os") or "—"), s_body),
            Paragraph(status_str, s_body),
            Paragraph(last_seen, s_body),
        ])
    if len(agents_rows) == 1:
        agents_rows.append([Paragraph("Aucun agent disponible", s_body), *[""] * 4])

    agents_tbl = Table(agents_rows, colWidths=[4.5*cm, 3.5*cm, 3.5*cm, 2.5*cm, 3.7*cm])
    agents_tbl.setStyle(TableStyle(
        _make_style_cmds(len(agents_rows), DARK_BLUE, LIGHT_GREY, MID_GREY)
    ))
    story.append(agents_tbl)
    story.append(PageBreak())

    # ── PAGE 5 : Pied de page audit ────────────────────────────────────────────

    story.append(Paragraph("PIED DE PAGE — TRAÇABILITÉ AUDIT", s_h2))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GREY, spaceAfter=16))

    footer_lines = [
        [Paragraph("Ce rapport a été généré automatiquement par Smart SIEM v1.0",
                   ps("f1", fontName="Helvetica", fontSize=10, textColor=TEXT_DARK))],
        [Paragraph("Confidentiel — Usage interne uniquement",
                   ps("f2", fontName="Helvetica-Bold", fontSize=10, textColor=RED_ACCENT))],
        [Paragraph("Conformité : ISO 27001 / RGPD",
                   ps("f3", fontName="Helvetica", fontSize=10, textColor=TEXT_LIGHT))],
        [Spacer(1, 0.4*cm)],
        [Paragraph(f"Date et heure de génération : {generated_str}",
                   ps("f4", fontName="Helvetica-Oblique", fontSize=9, textColor=TEXT_LIGHT))],
        [Paragraph(f"Analyste responsable : {analyst_username}",
                   ps("f5", fontName="Helvetica-Oblique", fontSize=9, textColor=TEXT_LIGHT))],
        [Paragraph(f"Période couverte : {period}",
                   ps("f6", fontName="Helvetica-Oblique", fontSize=9, textColor=TEXT_LIGHT))],
    ]
    footer_tbl = Table(footer_lines, colWidths=[17.7*cm])
    footer_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
        ("BOX",        (0, 0), (-1, -1), 1, MID_GREY),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 16),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(footer_tbl)

    doc.build(story)
    return buf.getvalue()


# ── Endpoint GET /generate ────────────────────────────────────────────────────

@router.get("/generate")
async def generate_pdf_report(
    period: str = Query(default="7d"),
    current_user: dict = Depends(get_current_user),
):
    """Génère et retourne un rapport PDF professionnel en temps réel."""
    analyst = current_user.get("username") or current_user.get("sub") or "Analyste"
    data = await _collect_report_data()
    pdf_bytes = _build_pdf(data, analyst, period)
    filename = f"smart-siem-report-{datetime.now().strftime('%Y-%m-%d')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
