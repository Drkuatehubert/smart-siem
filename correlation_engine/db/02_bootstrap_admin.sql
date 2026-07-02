-- Utilisateur système minimal requis comme created_by (FK) des règles de
-- corrélation seedées automatiquement par correlation_engine/seed_rules.py.
--
-- Ce n'est PAS un compte de connexion applicatif : l'authentification réelle
-- de l'API reste gérée par le backend FastAPI via Elasticsearch (idx-users).
-- Cette table `users` PostgreSQL sert uniquement au moteur de corrélation
-- (FK created_by/assigned_to/triggered_by sur ses propres tables).
INSERT INTO users (
    username, email, hashed_password, role,
    mfa_secret, mfa_enabled, must_change_password
) VALUES (
    'system-bootstrap',
    'system-bootstrap@smartsiem.local',
    crypt('not-a-login-account-' || gen_random_uuid()::text, gen_salt('bf', 12)),
    'admin',
    encode(gen_random_bytes(20), 'hex'),
    FALSE,
    TRUE
)
ON CONFLICT (username) DO NOTHING;
