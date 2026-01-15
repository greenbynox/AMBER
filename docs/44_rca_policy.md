# RCA policy

## Goal
Control when RCA summaries are auto‑published based on confidence.

## Model
- `rca_policies`
  - `project_id`
  - `min_confidence` (default 0.5)

## Behavior
- If `confidence < min_confidence`, RCA is stored but marked `published = false`.
- API/UI should hide or label withheld RCA outputs.
