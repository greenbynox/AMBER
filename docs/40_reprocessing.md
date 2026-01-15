# Reprocessing & analysis versioning

## Objectives
- Version all analysis algorithms (grouping, RCA, insights).
- Enable safe reprocessing and rollback.

## Data model
- `analysis_versions`: registered algorithm versions.
- `reprocess_jobs`: scoped reprocessing tasks (issue/project/time range).

## Guardrails
- No double counting.
- Audit trail of version transitions.
- Rollback supported per analysis type.

## Suggested workflow
1. Register new analysis version.
2. Run scoped reprocess job.
3. Compare diffs.
4. Promote or rollback.
