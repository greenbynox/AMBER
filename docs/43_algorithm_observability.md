# Algorithm observability

## Goal
Expose drift and instability in core algorithms (grouping, RCA).

## Metrics (ingest)
- `ember_grouping_default_total`
- `ember_grouping_rule_total`
- `ember_grouping_override_total`
- `ember_rca_confidence_sum`
- `ember_rca_confidence_count`

## Derived indicators
- Grouping churn (rate of overrides vs defaults).
- RCA confidence drift (avg confidence over time).

## Drift alerting
Drift thresholds are enforced via alert rules:
- `grouping_default_rate` (threshold is percent of default decisions).
- `rca_avg_confidence_below` (threshold is percent confidence).

## Next steps
- Persist daily algorithm health summaries.
