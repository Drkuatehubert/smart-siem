UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"login_failed"') WHERE name = 'Brute Force SSH (MITRE T1110)';
UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"large_outbound_transfer"') WHERE name LIKE 'Exfiltration%';
UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"connection_blocked"') WHERE name LIKE 'Scan de ports%';
UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"privilege_escalation"') WHERE name LIKE 'lévation%';
UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"login_success"') WHERE name LIKE 'Mouvement%';
UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"login_failed"') WHERE name LIKE 'Corr%';
SELECT name, conditions->>'event_action' as event_action FROM correlation_rules;
