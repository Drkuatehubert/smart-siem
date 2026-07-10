UPDATE correlation_rules 
SET conditions = jsonb_set(conditions, '{event_action}', '"sudo_exec"')
WHERE name LIKE '%vation%';
SELECT name, conditions->>'event_action' as event_action FROM correlation_rules WHERE name LIKE '%vation%';
