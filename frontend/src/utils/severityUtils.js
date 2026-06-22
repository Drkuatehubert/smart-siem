export const SEVERITY_COLORS = { info:"var(--color-primary)", warning:"var(--color-warning)", critical:"var(--color-danger)", HIGH:"var(--color-danger)", CRITICAL:"var(--color-critical)", INFO:"var(--color-primary)", WARNING:"var(--color-warning)" };
export const getSeverityColor = (s) => SEVERITY_COLORS[s] || "var(--color-muted)";
