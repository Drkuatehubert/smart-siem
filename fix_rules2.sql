UPDATE correlation_rules SET conditions = jsonb_set(conditions, '{event_action}', '"privilege_escalation"') WHERE name LIKE '%l%vation%';
SELECT name, conditions->>'event_action' as event_action FROM correlation_rules;
