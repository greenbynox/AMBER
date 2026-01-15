# Packaging (Windows / macOS / Linux)

## Windows
Run:
- `scripts/packaging/package.ps1`

Output:
- `dist/amber-windows/`
  - `bin/*.exe`
  - `scripts/start.cmd` + `scripts/start.ps1`
  - `.env.example`
  - `docker-min.zip` (optional)

## macOS / Linux
Run:
- `scripts/packaging/package.sh`

Output:
- `dist/amber-macos/` or `dist/amber-linux/`
  - `bin/` (release binaries)
  - `scripts/start.sh`
  - `.env.example`
  - `docker-min.zip` (optional)

## Notes
- The packaging scripts build binaries on the current OS.
- For cross‑platform builds, run on each OS or set up CI to build per target.
- `docker-min.zip` contains a minimal Postgres-only compose.
