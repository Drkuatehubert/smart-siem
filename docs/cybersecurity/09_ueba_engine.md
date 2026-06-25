# Documentation Module : Moteur UEBA et Intégration SOAR (`correlation/ueba/ueba_engine.py`)

Ce document détaille le fonctionnement, les exigences de sécurité et l'explication ligne par ligne du moteur comportemental **UEBA** et des modules associés.

---

## 1. Description Générale
Le module **UEBA (User and Entity Behavior Analytics)** modélise le comportement normal des utilisateurs et des machines sur 7 jours glissants afin de détecter des écarts par rapport à cette référence.

### Améliorations Apportées :
- **Profilage Enrichi** : Suivi des adresses IP, des machines (hosts), des pays d'origine (géolocalisation) et des applications clientes (user agents).
- **Détection Multi-Facteurs** : Connexions hors horaires habituels, volume anormal, IP source inconnue, machine inhabituelle, pays inhabituel (ex: connexion depuis l'étranger), user agent inconnu.
- **Score de Risque avec Decay** : Le score de risque accumulé diminue de 5% par heure pour éviter les faux-positifs persistants tout en conservant la mémoire des incidents récents.
- **Déclenchement SOAR Automatique** : Lorsque le score de risque global atteint ou dépasse `90`, le système déclenche de manière autonome le playbook de désactivation de compte (`disable_account`) sous politique fail-closed.

---

## 2. Explication Ligne par Ligne des Fichiers UEBA

### `correlation/ueba/profiler.py` (Profilage comportemental)
- **Lignes 1-13** : Imports et initialisation du logger.
- **Lignes 14-38** : Méthode `compute_profile` qui interroge les logs des 7 derniers jours pour un utilisateur ou une machine.
- **Lignes 39-44** : Agrégation Elasticsearch par intervalle d'une heure, par IP source, par host, par pays (`normalized_fields.geo_country.keyword`) et par agent utilisateur (`normalized_fields.user_agent.keyword`).
- **Lignes 45-56** : Extraction des heures d'activité typiques, calcul du volume moyen par heure, et indexation du profil final dans l'index `idx-ueba-profiles`.

### `correlation/ueba/anomaly_detector.py` (Détection d'anomalies)
- **Lignes 13-27** : Récupération du profil comportemental de référence de l'entité.
- **Lignes 28-34** : Évaluation temporelle : si l'heure de connexion actuelle n'est pas dans le profil -> pénalité de `+30` points.
- **Lignes 35-39** : Évaluation du volume : si le volume de logs dépasse 3x la moyenne historique -> pénalité de `+30` points.
- **Lignes 40-47** : Vérification de l'IP source (`+20` points) et de l'hôte (`+20` points).
- **Lignes 48-52** : Vérification de la géolocalisation / pays de connexion -> pénalité de `+25` points.
- **Lignes 53-57** : Vérification du User Agent / Navigateur -> pénalité de `+15` points.
- **Lignes 58-65** : Sauvegarde de l'événement anormal dans `idx-ueba-events` (score capé à 100).

### `correlation/ueba/risk_scorer.py` (Score dynamique avec decay)
- **Lignes 20-43** : Recherche de la dernière alerte UEBA dans `idx-alerts`. Calcul du temps écoulé et application de la formule de decay exponentiel (`prev_score * exp(-0.05 * hours_elapsed)`).
- **Lignes 44-51** : Combinaison du nouveau score d'anomalie et du score résiduel amorti.
- **Lignes 53-75** : Si le score consolidé est supérieur ou égal à 70, création d'une alerte dans `idx-alerts` de niveau `HIGH` ou `CRITICAL` (si >= 90) avec le contexte UEBA complet et recommandation SOAR automatique.

### `correlation/ueba/ueba_engine.py` (Orchestrateur)
- **Lignes 1-30** : Déclaration des dépendances et intégration avec le module de configuration du backend et l'exécuteur de playbooks SOAR.
- **Lignes 32-75** : Extraction des entités actives (utilisateurs, IPs, machines) sur la dernière heure via une agrégation Elasticsearch.
- **Lignes 76-90** : Pour chaque entité : création automatique d'un profil de référence si inexistant.
- **Lignes 91-105** : Évaluation des anomalies et calcul du score de risque dynamique (avec decay).
- **Lignes 106-135** : Si le score de risque consolidé dépasse `90`, construction d'une alerte critique et déclenchement automatique du playbook `disable_account` via `execute_playbook()`.
