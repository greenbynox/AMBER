$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RootDir

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Write-Host "Git n'est pas installé. Installe-le puis relance."
  exit 1
}

Write-Host "Mise à jour du code..."
git pull --rebase

Write-Host "Mise à jour infra (docker compose)..."
docker compose up -d

Write-Host "Rebuild services (release)..."
cargo build --release -p ember-api -p ember-ingest -p ember-worker

Write-Host "Upgrade terminé. Redémarre les services si besoin."