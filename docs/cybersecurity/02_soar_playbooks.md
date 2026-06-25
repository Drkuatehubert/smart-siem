# Documentation fichiers : playbooks SOAR

## `soar/playbooks/base_playbook.py`

- Definit le contrat commun des playbooks.
- `name` identifie le playbook dans les traces.
- `destructive` signale si l'action peut modifier l'infrastructure.
- `now` fournit un timestamp UTC uniforme.
- `success`, `skipped`, `failed` normalisent les sorties pour l'audit.
- `execute` est abstraite pour forcer chaque playbook a implementer son action.

## `soar/playbooks/block_ip.py`

- Extrait `source_ip` depuis l'alerte.
- Refuse si l'IP manque.
- Appelle `SoarPolicy.decide`.
- Reste en dry-run par defaut.
- N'appelle `iptables` que si le dry-run est desactive et la politique autorise l'action.
- Masque les details techniques en cas d'echec.

## `soar/playbooks/disable_account.py`

- Extrait `username` depuis l'alerte.
- Exige la validation SOAR.
- Protege les comptes `admin`, `root` et `elastic`.
- Cherche l'utilisateur dans `idx-users`.
- Met `is_active` a `False`.
- Retourne un resultat auditable avec `user_id`.

## `soar/playbooks/isolate_machine.py`

- Extrait `host` depuis l'alerte.
- Exige la validation SOAR.
- Prepare l'isolation sans executer d'action reseau aveugle.
- Retourne un statut utilisable par un connecteur EDR ou pare-feu.

## `soar/executor.py`

- Contient la liste blanche `PLAYBOOKS`.
- Refuse tout playbook inconnu.
- Execute le playbook choisi.
- Ecrit chaque resultat dans `idx-soar-executions`.
