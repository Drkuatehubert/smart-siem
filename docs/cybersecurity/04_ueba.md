# Documentation fichiers : UEBA

## `correlation/ueba/profiler.py`

- Calcule une baseline sur 7 jours.
- Agrege les heures typiques.
- Calcule le volume moyen par heure.
- Memorise les IP sources connues.
- Memorise les hosts connus.
- Persiste le profil dans `idx-ueba-profiles`.

## `correlation/ueba/anomaly_detector.py`

- Charge le profil UEBA.
- Detecte les connexions hors horaires habituels.
- Detecte les volumes superieurs a trois fois la moyenne.
- Detecte une IP source inconnue.
- Detecte un host inhabituel.
- Persiste l'evenement dans `idx-ueba-events`.

## `correlation/ueba/risk_scorer.py`

- Convertit le score UEBA en niveau SIEM.
- Cree une alerte a partir de 70.
- Recommande SOAR a partir de 90.
- Ajoute `source_ip`, `host`, `username` et `ueba_context` a l'alerte.
