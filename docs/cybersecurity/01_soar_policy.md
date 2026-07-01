# Documentation fichier : `soar/policy.py`

## Role

Ce fichier centralise la decision de securite avant execution d'un playbook SOAR.

## Logique ligne par ligne

- Imports : `ipaddress` valide les cibles IP, `os` lit les variables d'environnement, `dataclass` fige les decisions.
- `SEVERITY_ORDER` transforme les niveaux SIEM en ordre comparable.
- `_env_bool` force une lecture explicite des booleens pour eviter les interpretations ambigues.
- `SoarDecision` transporte trois informations : autorisation, raison, besoin d'approbation.
- `SoarPolicy.__init__` charge les garde-fous : kill-switch, approbation, reseaux prives, niveau minimal, dry-run.
- `decide` applique une politique fail-closed : si une condition est dangereuse ou incomplete, l'action est refusee.
- Le bloc IP valide le format IP et refuse par defaut loopback, link-local, multicast et reseaux prives.

## Variables

- `SOAR_KILL_SWITCH` : stoppe toute automatisation.
- `SOAR_REQUIRE_APPROVAL` : impose une validation humaine.
- `SOAR_ALLOW_PRIVATE_NETWORKS` : autorise explicitement les cibles RFC1918.
- `SOAR_MIN_AUTO_LEVEL` : niveau minimal pour automatiser.
- `SOAR_DRY_RUN` : simule les actions destructives.
