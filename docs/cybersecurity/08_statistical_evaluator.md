# Documentation Module : Évaluateur Statistique (`correlation/evaluators/statistical.py`)

Ce document détaille le fonctionnement, les exigences de sécurité et l'explication ligne par ligne du module `correlation/evaluators/statistical.py`.

---

## 1. Description Générale
L'évaluateur statistique implémente une détection d'anomalies basée sur le calcul dynamique d'un **Z-score** par rapport à une baseline historique (de 7 jours par défaut).
Il permet de détecter :
- Des pics anormaux de trafic/volume de logs (par exemple, des attaques par brute force ou déni de service).
- Des transferts anormaux de données (exfiltration) si un champ numérique (ex: `normalized_fields.bytes_sent`) est ciblé.

---

## 2. Structure et Paramètres de la Règle
Une règle de corrélation utilisant cet évaluateur possède les attributs suivants dans sa condition :
- `field` : (Optionnel) Le champ numérique sur lequel calculer les statistiques (ex: octets envoyés). Si absent, l'analyse se fait sur le volume de logs brut.
- `z_score_threshold` : Le seuil de déviation standard toléré (par défaut `3.0`).
- `min_events` : Nombre minimal d'événements requis dans la fenêtre courante pour que la règle s'applique (par défaut `10`).
- `baseline_window_s` : Période historique de référence en secondes (par défaut `604800` secondes, soit 7 jours).
- `bucket_interval_s` : Taille des segments temporels historiques en secondes (par défaut `3600` secondes, soit 1 heure).

---

## 3. Explication Ligne par Ligne du Code

### Imports et Initialisation (Lignes 1-18)
- **Lignes 1-10** : En-têtes, déclarations de types et imports standard (`math`, `datetime`, `logging`).
- **Ligne 12** : Import asynchrone du client officiel Elasticsearch.
- **Ligne 14** : Initialisation du logger dédié `correlation.evaluators.statistical`.
- **Lignes 16-18** : Définition de la classe `StatisticalEvaluator` avec son constructeur injectant le client Elasticsearch.

### Méthode `evaluate()` (Lignes 20-137)
- **Lignes 20-36** : Signature de la méthode de corrélation recevant la règle et retournant un tuple `(bool, List[str])`.
- **Lignes 37-43** : Extraction des paramètres de condition avec des valeurs par défaut sécurisées.
- **Lignes 45-48** : Calcul des dates de début de la baseline (`baseline_start`) et de la fenêtre d'évaluation courante (`eval_start`).

### Récupération de la Fenêtre Courante (Lignes 50-77)
- **Lignes 50-63** : Préparation de la requête Elasticsearch filtrant les logs de la fenêtre d'évaluation.
- **Lignes 65-70** : Exécution de la recherche Elasticsearch (limité à 100 hits pour des raisons de performance).
- **Lignes 72-77** : Vérification du nombre d'événements minimum (`min_events`). Si insuffisant, retour précoce de `False`.

### Calcul de la Valeur Courante (Lignes 79-88)
- **Lignes 79-85** : Si un champ spécifique est configuré, somme dynamique des valeurs de ce champ sur les logs récupérés.
- **Lignes 86-88** : Si aucun champ n'est défini, la valeur courante est simplement le compte de documents.

### Récupération de la Baseline Historique (Lignes 90-128)
- **Lignes 90-101** : Préparation de la requête sur la période historique (`baseline_start` à `eval_start`).
- **Lignes 103-116** : Agrégation en histogramme temporel (`date_histogram`) découpé en intervalles définis. Si un champ est configuré, on y ajoute une sous-agrégation de somme (`metric_sum`).
- **Lignes 118-120** : Exécution de la requête Elasticsearch de baseline avec `size=0` pour des performances optimales.
- **Lignes 122-128** : Extraction des buckets et construction de la liste des valeurs de référence. Validation de la taille de l'historique (minimum 3 points requis).

### Calculs Statistiques et Z-Score (Lignes 130-155)
- **Lignes 130-134** : Calcul de la moyenne historique et de la variance de la baseline.
- **Lignes 135** : Calcul de l'écart-type (`stddev = math.sqrt(variance)`).
- **Lignes 137-145** : Calcul du Z-score en évitant la division par zéro (si l'écart-type est nul).
- **Lignes 147-155** : Évaluation du Z-score par rapport au seuil de la règle. Si `z_score >= z_threshold`, log warning et retour de `True` avec les IDs des logs corrélés.
