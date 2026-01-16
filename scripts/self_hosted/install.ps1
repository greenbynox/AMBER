$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $RootDir

if (-not (Test-Path ".env")) {
  if (Test-Path ".env.example") {
    Copy-Item ".env.example" ".env"
  } else {
    "DATABASE_URL=postgres://ember:ember@localhost:5432/ember`nEMBER_SECRET=change_me`nEMBER_JWT_SECRET=change_me_jwt`nEMBER_SECRETS_KEY=BASE64_32_BYTES" | Set-Content ".env" -Encoding UTF8
  }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "Docker n'est pas installé. Installe-le puis relance."
  exit 1
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  Write-Host "Cargo n'est pas installé. Installe Rust puis relance."
  exit 1
}

Write-Host "Démarrage infra (docker compose)..."
docker compose up -d

Write-Host "Build services (release)..."
cargo build --release -p ember-api -p ember-ingest -p ember-worker

if (-not (Test-Path "logs")) {
  New-Item -ItemType Directory -Path "logs" | Out-Null
}

Write-Host "Installation terminée."
Write-Host "Pour démarrer: .\scripts\start.ps1"