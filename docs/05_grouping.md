# Grouping

## Approach
- Deterministic first (stable fingerprint).
- Probabilistic next (fuzzy, tokens) if needed.

## Noise reduction
- Ignore irrelevant frames (deps, runtime).
- Heavier weight on application frames.

## Tradeoffs
- Deterministic = fewer false merges.
- Probabilistic = less noise but risk of over‑grouping.

## Overrides (manual)
If a fingerprint must be merged into another, create a grouping override.
- Overrides map `source_fingerprint` → `target_fingerprint`.
- You can use issue IDs instead of raw fingerprints.
- New events will follow the override.
