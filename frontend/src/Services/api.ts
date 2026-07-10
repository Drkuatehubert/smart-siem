// src/Services/api.ts
import { AuthService } from "./authService";
import { IncidentService } from "./incidentService";
import { LogService } from "./logService";
import { AlertService } from "./alertService";
import { RuleService } from "./ruleService";
import { ThreatIntelService } from "./threatIntelService";
import { AgentService } from "./agentService";
import { VulnerabilityService } from "./vulnerabilityService";
import { PlaybookService } from "./playbookService";
import { ComplianceService } from "./complianceService";
import { UebaService } from "./uebaService";
import { ReportService } from "./reportService";
import { UserService } from "./userService";
import { AuditLogService } from "./auditLogService";
import { DashboardService } from "./dashboardService";
import { SoarService } from "./soarService";

// Create instances of all services
const authService = new AuthService();
const incidentService = new IncidentService();
const logService = new LogService();
const alertService = new AlertService();
const ruleService = new RuleService();
const threatIntelService = new ThreatIntelService();
const agentService = new AgentService();
const vulnerabilityService = new VulnerabilityService();
const playbookService = new PlaybookService();
const complianceService = new ComplianceService();
const uebaService = new UebaService();
const reportService = new ReportService();
const userService = new UserService();
const auditLogService = new AuditLogService();
const dashboardService = new DashboardService();
const soarService = new SoarService();

// Export a unified API object
export const api = {
  // Auth
  login: authService.login.bind(authService),
  logout: authService.logout.bind(authService),
  getProfile: authService.getProfile.bind(authService),
  verifyTotp: authService.verifyTotp.bind(authService),

  // Logs (LogEvent)
  getLogs: logService.getLogs.bind(logService),
  getLogsPage: logService.getLogsPage.bind(logService),
  getEventActions: logService.getEventActions.bind(logService),
  getLogById: logService.getLogById.bind(logService),
  getRawLogs: logService.getRawLogs.bind(logService),
  getLogSources: logService.getLogSources.bind(logService),

  // Alerts
  getAlerts: alertService.getAlerts.bind(alertService),
  getAlertById: alertService.getAlertById.bind(alertService),
  acknowledgeAlert: alertService.acknowledgeAlert.bind(alertService),
  updateAlertStatus: alertService.updateAlertStatus.bind(alertService),
  triggerSoar: alertService.triggerSoar.bind(alertService),

  // Incidents
  getIncidents: incidentService.getIncidents.bind(incidentService),
  getIncidentById: incidentService.getIncidentById.bind(incidentService),
  createIncident: incidentService.createIncident.bind(incidentService),
  updateIncidentStatus:
    incidentService.updateIncidentStatus.bind(incidentService),
  assignIncident: incidentService.assignIncident.bind(incidentService),
  addResponseAction: incidentService.addResponseAction.bind(incidentService),

  // Rules
  getRules: ruleService.getRules.bind(ruleService),
  getRuleById: ruleService.getRuleById.bind(ruleService),
  addRule: ruleService.addRule.bind(ruleService),
  toggleRule: ruleService.toggleRule.bind(ruleService),
  updateRule: ruleService.updateRule.bind(ruleService),

  // Threat Intel
  getThreatIntel: threatIntelService.getThreatIntel.bind(threatIntelService),
  addThreatIndicator:
    threatIntelService.addThreatIndicator.bind(threatIntelService),

  // Agents (Log Sources + Health)
  getAgents: agentService.getAgents.bind(agentService),
  getAgentById: agentService.getAgentById.bind(agentService),

  // Vulnerabilities
  getVulnerabilities:
    vulnerabilityService.getVulnerabilities.bind(vulnerabilityService),
  updateVulnStatus:
    vulnerabilityService.updateVulnStatus.bind(vulnerabilityService),

  // Playbooks
  getPlaybooks: playbookService.getPlaybooks.bind(playbookService),
  getPlaybookById: playbookService.getPlaybookById.bind(playbookService),
  createPlaybook: playbookService.createPlaybook.bind(playbookService),
  triggerPlaybook: playbookService.triggerPlaybook.bind(playbookService),

  // Compliance
  getCompliance: complianceService.getCompliance.bind(complianceService),
  updateComplianceStatus:
    complianceService.updateComplianceStatus.bind(complianceService),

  // UEBA
  getUebaProfiles: uebaService.getProfiles.bind(uebaService),
  getUebaProfileByEntity: uebaService.getProfileByEntity.bind(uebaService),
  computeUebaProfiles: uebaService.computeProfiles.bind(uebaService),

  // Reports
  getReports: reportService.getReports.bind(reportService),
  generateReport: reportService.generateReport.bind(reportService),

  // Users
  getUsers: userService.getUsers.bind(userService),
  getUserById: userService.getUserById.bind(userService),
  createUser: userService.createUser.bind(userService),
  lockUser: userService.lockUser.bind(userService),
  updateRole: userService.updateRole.bind(userService),
  enableUser: userService.enableUser.bind(userService),
  disableUser: userService.disableUser.bind(userService),
  resetPassword: userService.resetPassword.bind(userService),
  getUserActivity: userService.getUserActivity.bind(userService),

  // Audit Logs
  getAuditLogs: auditLogService.getAuditLogs.bind(auditLogService),

  // Dashboard
  getDashboardSummary: dashboardService.getSummary.bind(dashboardService),

  // SOAR Management
  getSoarHistory: soarService.getHistory.bind(soarService),
  soarBlockIp: soarService.blockIp.bind(soarService),
  soarDisableAccount: soarService.disableAccount.bind(soarService),
  getBlockedIps: soarService.getBlockedIps.bind(soarService),
  unblockIp: soarService.unblockIp.bind(soarService),
  getDisabledAccounts: soarService.getDisabledAccounts.bind(soarService),
  enableAccount: soarService.enableAccount.bind(soarService),
};

// Default export for backward compatibility
export default api;
