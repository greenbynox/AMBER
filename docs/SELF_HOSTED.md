# Self‑hosted install & upgrade

## Prérequis
- Docker Desktop (ou Docker Engine)
- Rust (cargo)
- Git

## Installation (Windows)
- Lance `scripts/self_hosted/install.ps1`
- Démarre les services avec `scripts/start.ps1`

## Installation (Linux/macOS)
- Lance `scripts/self_hosted/install.sh`
- Démarre les services avec `scripts/start.sh`

## Upgrade
- Windows: `scripts/self_hosted/upgrade.ps1`
- Linux/macOS: `scripts/self_hosted/upgrade.sh`

## UI
La UI React se lance séparément:
- `cd apps/web`
- `npm install`
- `npm run dev`

## Notes
- Les scripts installent/upgrade l’infra Docker + buildent les binaires Rust.
- Redémarre les services après upgrade si nécessaire.
