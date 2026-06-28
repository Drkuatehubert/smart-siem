// src/Services/index.ts
import { AuthService } from './authService';
import { IncidentService } from './incidentService';
import { LogService } from './logService';
import { RuleService } from './ruleService';
import { ThreatIntelService } from './threatIntelService';
import { AgentService } from './agentService';
import { VulnerabilityService } from './vulnerabilityService';
import { PlaybookService } from './playbookService';
import { ComplianceService } from './complianceService';
import { UebaService } from './uebaService';
import { ReportService } from './reportService';
import { UserService } from './userService';
import { AuditLogService } from './auditLogService';

// Create instances of all services
const authService = new AuthService();
const incidentService = new IncidentService();
const logService = new LogService();
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

// Export a unified API object that matches the original structure
export const api = {
  // Auth
  login: authService.login.bind(authService),
  logout: authService.logout.bind(authService),
  getProfile: authService.getProfile.bind(authService),

  // Incidents
  getIncidents: incidentService.getIncidents.bind(incidentService),
  getIncidentById: incidentService.getIncidentById.bind(incidentService),
  createIncident: incidentService.createIncident.bind(incidentService),
  updateIncidentStatus: incidentService.updateIncidentStatus.bind(incidentService),
  addIncidentComment: incidentService.addIncidentComment.bind(incidentService),
  assignIncident: incidentService.assignIncident.bind(incidentService),

  // Logs
  getLogs: logService.getLogs.bind(logService),
  getLogById: logService.getLogById.bind(logService),
  addLog: logService.addLog.bind(logService),

  // Rules
  getRules: ruleService.getRules.bind(ruleService),
  getRuleById: ruleService.getRuleById.bind(ruleService),
  addRule: ruleService.addRule.bind(ruleService),
  toggleRule: ruleService.toggleRule.bind(ruleService),

  // Threat Intel
  getThreatIntel: threatIntelService.getThreatIntel.bind(threatIntelService),
  addThreatIndicator: threatIntelService.addThreatIndicator.bind(threatIntelService),

  // Agents
  getAgents: agentService.getAgents.bind(agentService),
  getAgentById: agentService.getAgentById.bind(agentService),

  // Vulnerabilities
  getVulnerabilities: vulnerabilityService.getVulnerabilities.bind(vulnerabilityService),
  updateVulnStatus: vulnerabilityService.updateVulnStatus.bind(vulnerabilityService),

  // Playbooks
  getPlaybooks: playbookService.getPlaybooks.bind(playbookService),
  triggerPlaybook: playbookService.triggerPlaybook.bind(playbookService),

  // Compliance
  getCompliance: complianceService.getCompliance.bind(complianceService),
  updateComplianceStatus: complianceService.updateComplianceStatus.bind(complianceService),

  // UEBA
  getAnomalies: uebaService.getAnomalies.bind(uebaService),

  // Reports
  getReports: reportService.getReports.bind(reportService),
  generateReport: reportService.generateReport.bind(reportService),

  // Users
  getUsers: userService.getUsers.bind(userService),
  createUser: userService.createUser.bind(userService),

  // Audit Logs
  getAuditLogs: auditLogService.getAuditLogs.bind(auditLogService),
};

// Default export for backward compatibility
export default api;