# Root Cause Analysis (RCA)

## Realistic
- Link errors to releases.
- Explain the likely regression.
- Highlight suspicious frames.

## RCA assistant v1
- **Causal chain**: ordered list of suspect frames (prioritize in-app frames).
- **Regression map**: first/last release, regression timestamp, suspect commits (if available).
- **Confidence**: a heuristic score exposed alongside the summary.

## Not magic
- No “auto‑fix”.
- Always provide a confidence level.
- Human summary with visible evidence.
