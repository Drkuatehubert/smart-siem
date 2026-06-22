# Rapport de Sécurité — Smart SIEM
**Responsable** : Chef de Projet & Sécurité  
**Exigences couvertes** : NFR-SEC-01/02/03, RF-SEC-01/02/03/04

---

## 1. Chiffrement en Transit (TLS)

| Flux | Protocole | Port | Statut |
|---|---|---|---|
| Client → Nginx | HTTPS/TLS 1.2+ | 443 | ✅ Actif |
| Nginx → Backend | HTTP interne | 8000 | ✅ Réseau Docker isolé |
| Sources → Syslog | TLS | 6514 | ✅ Cert auto-signé |
| Sources → API | HTTPS | 443 | ✅ Via Nginx |

**NFR-SEC-01** : Toutes les communications externes utilisent TLS 1.2 minimum.

---

## 2. Chiffrement au Repos

- Volumes Elasticsearch chiffrés via `xpack.security.enabled: true`
- Mots de passe stockés en **bcrypt (rounds=12)** — jamais en clair
- **NFR-SEC-02** : Hash bcrypt/argon2, jamais de stockage en clair ✅

---

## 3. Authentification & Sessions JWT

- Tokens JWT signés HS256, expiration configurable (`JWT_EXPIRY_MINUTES`)
- Payload : `user_id`, `username`, `role`, `org_scope`, `exp`, `iat`
- Transmission via header `Authorization: Bearer <token>`
- **NFR-SEC-03** : JWT à expiration courte + mécanisme de renouvellement ✅

---

## 4. RBAC — Matrice des Permissions

| Permission | Lecteur | Analyste | Admin |
|---|:---:|:---:|:---:|
| logs:read | ✅ | ✅ | ✅ |
| logs:search | ✅ | ✅ | ✅ |
| alerts:read | ✅ | ✅ | ✅ |
| alerts:update | ❌ | ✅ | ✅ |
| playbooks:execute | ❌ | ✅ | ✅ |
| reports:generate | ❌ | ✅ | ✅ |
| audit:read | ❌ | ❌ | ✅ |
| users:manage | ❌ | ❌ | ✅ |
| rules:manage | ❌ | ❌ | ✅ |
| retention:update | ❌ | ❌ | ✅ |

**RF-SEC-02** : RBAC implémenté via `rbac.py` avec décorateurs FastAPI ✅

---

## 5. Journal d'Audit (RF-SEC-03)

Actions tracées dans `idx-audit-log` (append-only) :

| Action | Déclencheur |
|---|---|
| `connexion` | POST /auth/login succès |
| `deconnexion` | POST /auth/logout |
| `creation_utilisateur` | POST /users |
| `modification_role` | PATCH /users/{id}/role |
| `consultation_alerte` | GET /alerts/{id} |
| `traitement_alerte` | PATCH /alerts/{id}/status |

Chaque entrée contient : `user_id`, `action`, `ip_address`, `created_at`, `details`.

---

## 6. Ségrégation Organisationnelle (RF-SEC-04)

- Champ `org_scope` sur chaque utilisateur (filiale / service / équipe)
- Les requêtes ES intègrent automatiquement un filtre sur `org_scope`
- Un Administrateur voit tout, les autres uniquement leur périmètre

---

## 7. Conformité

### RGPD
- Minimisation des données : seuls les champs nécessaires sont collectés
- Durée de conservation configurable (`LOG_RETENTION_DAYS`)
- Traçabilité des accès : journal d'audit complet

### ISO 27001
- Gestion des accès formalisée (RBAC documenté)
- Journalisation des actions sensibles
- Revue périodique recommandée des comptes actifs
