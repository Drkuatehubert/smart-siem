from fastapi import APIRouter
from app.api.v1.auth.router import router as auth_router
from app.api.v1.audit.router import router as audit_router
from app.api.v1.users.router import router as users_router
from app.api.v1.alerts.router import router as alerts_router
from app.api.v1.incidents.router import router as incidents_router
from app.api.v1.rules.router import router as rules_router
from app.api.v1.sources.router import router as sources_router
from app.api.v1.dashboard.router import router as dashboard_router
from app.api.v1.reports.router import router as reports_router
from app.api.v1.logs.router import router as logs_router
from app.api.v1.agents.router import router as agents_router
from app.api.v1.ueba.router import router as ueba_router

from app.api.v1.playbooks.router import router as playbooks_router
from app.api.v1.compliance.router import router as compliance_router
from app.api.v1.vulnerabilities.router import router as vulnerabilities_router
from app.api.v1.threat_intel.router import router as threat_intel_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(audit_router)
api_router.include_router(users_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(rules_router)
api_router.include_router(sources_router)
api_router.include_router(dashboard_router)
api_router.include_router(reports_router)
api_router.include_router(logs_router)
api_router.include_router(agents_router)
api_router.include_router(ueba_router)
api_router.include_router(playbooks_router)
api_router.include_router(compliance_router)
api_router.include_router(vulnerabilities_router)
api_router.include_router(threat_intel_router)
