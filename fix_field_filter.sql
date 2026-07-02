UPDATE correlation_rules 
SET conditions = conditions - 'field_filter'
WHERE conditions ? 'field_filter' 
AND conditions->'field_filter'->>'field' = '';
SELECT name, conditions FROM correlation_rules;
