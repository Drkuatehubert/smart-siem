# Documentation fichiers : normalizer

## `collectors/normalizer/tagger.py`

- Lit `raw_message`.
- Classe la severite en `critical`, `warning` ou `info`.
- Classe le type en `auth`, `network`, `endpoint` ou `application`.
- Retourne une copie enrichie du log.

## `collectors/normalizer/schema.py`

- Cree `log_id`.
- Pose `timestamp` UTC.
- Garantit les champs requis par le cahier des charges : host, IP, type, severite, message brut.
- Ajoute les champs SIEM : `normalized_fields`, `tags`, `is_flagged`, `archived`, `retention_expiry`.

## `collectors/normalizer/Dockerfile`

- Fournit une image minimale pour satisfaire le service `normalizer` du compose.
