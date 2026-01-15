Param(
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent | Split-Path -Parent
Set-Location $root

$dist = Join-Path $root $OutDir
if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }

Write-Host "Build Windows release binaries..." -ForegroundColor Cyan
cargo build --release -p ember-api -p ember-ingest -p ember-worker -p ember-launcher

$winDir = Join-Path $dist "amber-windows"
if (Test-Path $winDir) { Remove-Item $winDir -Recurse -Force }
New-Item -ItemType Directory -Path $winDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $winDir "bin") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $winDir "scripts") | Out-Null

Copy-Item "$root\target\release\ember-api.exe" "$winDir\bin\" -Force
Copy-Item "$root\target\release\ember-ingest.exe" "$winDir\bin\" -Force
Copy-Item "$root\target\release\ember-worker.exe" "$winDir\bin\" -Force
Copy-Item "$root\target\release\ember-launcher.exe" "$winDir\bin\" -Force
Copy-Item "$root\scripts\start.cmd" "$winDir\scripts\" -Force
Copy-Item "$root\scripts\start.ps1" "$winDir\scripts\" -Force
Copy-Item "$root\.env.example" "$winDir\" -Force
Copy-Item "$root\docker-min.zip" "$winDir\" -Force -ErrorAction SilentlyContinue

Write-Host "Windows package ready: $winDir" -ForegroundColor Green
