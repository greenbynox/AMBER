# Roadmap AMBER → niveau Sentry (factuel, actionnable)

_Date: 15 Jan 2026_

Ce document transforme les manques techniques constatés en **roadmap exécutable**, organisée par domaines d’ingénierie. Objectif: combler les écarts fonctionnels et d’industrialisation pour atteindre le niveau Sentry (qualité, robustesse, UX, écosystème).

---

## 0) Principes d’exécution
- **Chaque étape = livrable testable + doc + métrique**.
- **Versionner** tout ce qui impacte le comportement (schemas, grouping, RCA, reprocess).
- **Invariants écrits** avant l’implémentation.
- **Tests de défaillance** obligatoires pour valider la robustesse.
- **Déterminisme défini**: déterministe à input égal + version d’algo égale; non‑déterminisme autorisé uniquement si versionné.

---

## 0.b) Non‑objectifs explicites (santé système)
- Pas de **debugging live** en prod.
- Pas de **mutation silencieuse** des issues.
- Pas de RCA auto si la **confidence** est < seuil défini.

---

## 0.c) Ownership & responsabilité
- **Issue**: propriétaire humain explicite (assignee) avec override sur l’automatisation.
- **Grouping rule**: propriétaire et historique de changements (audit).
- **RCA conclusion**: explicite “auto” vs “reviewed by human”.
- **Principe**: l’automatisation **s’efface** quand l’humain a statué.

---

## 1) Invariants techniques explicites (CRITIQUE)

### Objectif
Rendre les garanties **formelles** (et donc vérifiables). C’est le socle d’un système supérieur à Sentry.

### Livrables
- `docs/INVARIANTS.md`
- Tests d’invariants (unit/integration + chaos minimal)

### Invariants minimaux à formaliser
1. **Stabilité du grouping**: même event → même issue (à contexte invariant).
2. **Idempotence ingestion**: retry safe (pas de double comptage).
3. **Ordering guarantees**: event/release/insight cohérents.
4. **Replay safety**: aucune session partiellement écrite exposée.

### Invariants data‑level (à expliciter)
- **No ghost data**: aucune issue sans events.
- **No dangling references**: `signal_links` toujours résolvables.
- **Monotonic counters**: `event_count`, `first_seen`, `last_seen` ne régressent pas.
- **Immutability rules**: champs write‑once explicités (ex: `first_seen`, `first_release`).

### Tests à écrire
- Tests qui violent volontairement chaque invariant (red tests).

---

## 2) Reprocessing & backfill contrôlé (STRUCTUREL)

### Objectif
Recalculer grouping/RCA/insights **sans perte ni double comptage**, avec versionning.

### Livrables
- Table `analysis_versions` (type, version, deployed_at, rollback_to)
- Job `reprocess` (issue_id | project_id | time_range)
- Garde‑fou double comptage + journal d’exécution

### Résultat attendu
- Capacité de **rollback** (RCA v1 → v2) sans casser l’historique.
- Diff clair des changements d’analyse.

---

## 3) Failure modes explicitement testés (ROBUSTESSE)

### Objectif
Démontrer la stabilité sous pannes.

### Livrables
- `chaos/` harness minimal + docs
- Scénarios reproductibles + résultats attendus

### Scénarios prioritaires
- Postgres en lecture seule
- ClickHouse indisponible
- Kafka lent / lag important
- Quota atteint mid‑ingest

---

## 4) Corrélation inter‑signaux (DATA MODEL)

### Objectif
Persister les liens entre signaux pour un diagnostic **rapide et déterministe**.

### Livrables
- Table `signal_links` (issue ↔ trace ↔ replay ↔ deploy)
- Scores persistés (corrélation)

### Résultat attendu
- Latence plus faible que corrélation à la volée.
- Diagnostic plus stable (moins de variations UI).

---

## 5) Grouping auditability (AVANTAGE COMPÉTITIF)

### Objectif
Permettre: “Pourquoi cet event est dans cette issue ?”

### Livrables
- Tables `grouping_decisions`, `grouping_rules_applied`
- Version du fingerprint algo stockée par event
- Diff avant/après regrouping

### Résultat attendu
- Audit et debug précis (preuve technique).

---

## 6) Modèle de coût déterministe (FINOPS)

### Objectif
Garantir un coût borné par event.

### Livrables
- `event_cost_units` (CPU/storage/egress)
- Projection mensuelle par projet
- Refus gracieux (drop + summary)

---

## 7) Versioning des schémas & compatibilité SDK

### Objectif
Éviter les cassures clients à long terme.

### Livrables
- `event.schema.vN.json`
- Validation stricte par version
- Politique de dépréciation documentée

---

## 8) Observabilité des algorithmes (META‑OPS)

### Objectif
Observer les algorithmes eux‑mêmes.

### Livrables
- Métriques: grouping churn, RCA drift, split/merge rate
- Alerting sur dérives

---

# Roadmap séquencée (12 mois)

## Trimestre 1 — Robustesse & garanties (priorité absolue)
1. `INVARIANTS.md` + tests rouges.
2. Reprocessing v1 + `analysis_versions`.
3. Chaos harness minimal + scénarios critiques.

## Trimestre 2 — Auditabilité & corrélations
4. `grouping_decisions` + versioning fingerprint.
5. `signal_links` + scores persistés.

## Trimestre 3 — Coût & compatibilité long terme
6. Modèle coût déterministe + refus gracieux.
7. Schemas versionnés + validation stricte SDK.

## Trimestre 4 — Algorithmes maîtrisés
8. Observabilité algos + alerting sur dérives.
9. RCA v2 (versionnée) avec rollback complet.

---

# Résumé ultra‑court (5 priorités)
1. Invariants écrits + testés
2. Reprocessing versionné
3. Failure modes testés
4. Auditabilité grouping
5. Corrélation persistée inter‑signaux

---

# Positionnement vs Sentry
Si ces 5 points sont livrés proprement, AMBER devient **techniquement plus prouvable** et **plus déterministe** que Sentry sur la stabilité, la traçabilité et le coût.

---

# Documentation (langue)
- **Docs/Specs/Schémas/Contrats**: anglais uniquement (précision et standardisation).
- **Commentaires de code**: courts, tolérés en FR si utile.
