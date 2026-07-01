# Documentation Module : Configuration TLS des Notificateurs (`soar/notifiers/tls_config.py`)

Ce document détaille le fonctionnement, les exigences de sécurité et l'explication ligne par ligne du module `soar/notifiers/tls_config.py`.

---

## 1. Description Générale
Le module `soar/notifiers/tls_config.py` centralise la configuration des contextes SSL/TLS pour l'ensemble des modules de notification du SOAR.
Il garantit que les connexions sortantes vers :
- Les serveurs de messagerie SMTP (STARTTLS)
- Les webhooks d'alertes (ex: Slack, Microsoft Teams)
- Les serveurs de ticketing (ex: Jira, GLPI)

respectent scrupuleusement la politique de sécurité en interdisant les suites de chiffrement et versions de protocoles obsolètes.

---

## 2. Explication Ligne par Ligne du Code

### Imports et Log (Lignes 1-16)
- **Lignes 1-13** : Déclarations de types et imports standard (`os`, `ssl`, `logging`).
- **Ligne 14** : Import de la fonction centrale de construction de contexte TLS `build_ssl_context` depuis `soar.tls_client`.
- **Ligne 16** : Initialisation du logger `soar.notifiers.tls_config`.

### Fonction `get_smtp_ssl_context()` (Lignes 18-35)
- **Lignes 18-24** : Définition de la fonction recevant optionnellement un bundle CA et retournant un `ssl.SSLContext` durci.
- **Ligne 25** : Récupération du bundle CA configuré via la variable d'environnement `TLS_CA_BUNDLE`.
- **Ligne 26** : Création du contexte SSL par défaut sécurisé.
- **Ligne 27** : Restriction stricte de la version minimale à **TLS 1.2** (interdisant SSLv3, TLS 1.0 et 1.1).
- **Lignes 29-35** : Chargement du bundle CA personnalisé s'il existe sur le disque, ou chargement des certificats de l'autorité de certification système par défaut.

### Fonction `get_http_ssl_context()` (Lignes 37-43)
- **Lignes 37-43** : Wrapper asynchrone retournant un contexte SSL pour les appels HTTP/HTTPS en déléguant directement au constructeur centralisé `build_ssl_context(verify=verify)`. En production, la désactivation de la vérification est refusée.
