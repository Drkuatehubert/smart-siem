# Documentation fichiers : correlation

## `correlation/evaluators/cross_source.py`

- Ajoute un evaluateur de correlation inter-sources.
- Lit les `steps` de la regle.
- Applique une fenetre temporelle.
- Recherche les logs correspondant a au moins une etape.
- Groupe les hits par entite (`normalized_fields.username` par defaut).
- Verifie que l'entite apparait dans au moins `min_sources`.
- Retourne les IDs de logs utiles a l'alerte.

## `correlation/rule_loader.py`

- Autorise le nouveau type de regle `cross_source`.
- Conserve la validation stricte des niveaux, MITRE IDs et phases kill-chain.

## `correlation/engine.py`

- Importe `CrossSourceEvaluator`.
- Route les regles `cross_source` vers le nouvel evaluateur.
- Ajoute dans les alertes : `soar_recommended`, `soar_approved`, `ueba_context`.
- Les alertes critiques peuvent donc etre traitees par un workflow SOAR avec validation.

## `correlation/rules/cross_source_account_compromise.yaml`

- Regle MITRE T1078 pour abus de comptes valides.
- Cherche une meme entite vue dans plusieurs sources.
- Genere une alerte `CRITICAL`.
