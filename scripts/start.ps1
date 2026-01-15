Param(
    [switch]$NoBrowser,
    [string]$LogPath = ""
)

function Test-DockerDaemon {
    try {
        $null = & docker info 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Start-DockerDesktop {
    $paths = @(
        "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe",
        "$env:ProgramFiles(x86)\Docker\Docker\Docker Desktop.exe"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            Start-Process -FilePath $path | Out-Null
            return
        }
    }

    try {
        Start-Process -FilePath "Docker Desktop" | Out-Null
    } catch {
        # ignore
    }
}

function Wait-DockerDaemon {
    param([int]$TimeoutSeconds = 30)
    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        if (Test-DockerDaemon) { return $true }
        Start-Sleep -Seconds 2
        $elapsed += 2
    }
    return $false
}

function Install-DockerDesktop {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        return (Install-DockerDesktopFromWeb)
    }

    Write-Host "Installation Docker Desktop via winget..." -ForegroundColor Cyan
    $proc = Start-Process -FilePath "winget" -ArgumentList @(
        "install",
        "--id",
        "Docker.DockerDesktop",
        "-e",
        "--accept-package-agreements",
        "--accept-source-agreements"
    ) -Wait -PassThru

    return ($proc.ExitCode -eq 0)
}

function Install-DockerDesktopFromWeb {
    $url = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    $temp = Join-Path $env:TEMP "DockerDesktopInstaller.exe"

    Write-Host "Téléchargement Docker Desktop..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $url -OutFile $temp -UseBasicParsing
    } catch {
        Write-Host "Téléchargement impossible." -ForegroundColor Yellow
        return $false
    }

    Write-Host "Installation Docker Desktop (silencieuse)..." -ForegroundColor Cyan
    try {
        $proc = Start-Process -FilePath $temp -ArgumentList @("install", "--quiet") -Wait -PassThru
        return ($proc.ExitCode -eq 0)
    } catch {
        return $false
    }
}

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
if ($LogPath) {
    $logDir = Split-Path -Parent $LogPath
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    Start-Transcript -Path $LogPath -Append | Out-Null
}
Set-Location $root

if (-not (Test-Path "$root\.env")) {
    if (Test-Path "$root\.env.example") {
        Copy-Item "$root\.env.example" "$root\.env" -Force
    } else {
        "DATABASE_URL=postgres://ember:ember@localhost:5432/ember`nEMBER_SECRET=change_me`nEMBER_JWT_SECRET=change_me_jwt`nEMBER_SECRETS_KEY=BASE64_32_BYTES" | Set-Content "$root\.env"
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker Desktop n'est pas installé. Tentative d'installation automatique..." -ForegroundColor Yellow
    $installed = Install-DockerDesktop
    if ($installed) {
        Write-Host "Installation terminée. Démarrage de Docker Desktop..." -ForegroundColor Cyan
        Start-DockerDesktop
        if (-not (Wait-DockerDaemon -TimeoutSeconds 60)) {
            Write-Host "Docker Desktop installé mais pas prêt." -ForegroundColor Yellow
            Write-Host "Relance ce script après ouverture complète de Docker Desktop." -ForegroundColor Yellow
            if ($LogPath) { Stop-Transcript | Out-Null }
            pause
            exit 1
        }
    } else {
        $zipPath = Join-Path $root "docker-min.zip"
        $srcPath = Join-Path $root "docker-min"
        if (-not (Test-Path $zipPath) -and (Test-Path $srcPath)) {
            Compress-Archive -Path (Join-Path $srcPath "*") -DestinationPath $zipPath -Force
        }
        Write-Host "Installation automatique impossible." -ForegroundColor Yellow
        if (Test-Path $zipPath) {
            Write-Host "Bundle minimal disponible: $zipPath" -ForegroundColor Cyan
        }
        Write-Host "Installe Docker Desktop manuellement, puis relance." -ForegroundColor Yellow
        if ($LogPath) { Stop-Transcript | Out-Null }
        pause
        exit 1
    }
}

if (-not (Test-DockerDaemon)) {
    Write-Host "Docker Desktop est installé mais pas démarré. Tentative de lancement..." -ForegroundColor Yellow
    Start-DockerDesktop
    if (-not (Wait-DockerDaemon -TimeoutSeconds 45)) {
        Write-Host "Docker Desktop n'est toujours pas prêt." -ForegroundColor Yellow
        Write-Host "Lance Docker Desktop en tant qu'administrateur, puis relance." -ForegroundColor Yellow
        if ($LogPath) { Stop-Transcript | Out-Null }
        pause
        exit 1
    }
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Rust/Cargo n'est pas installé." -ForegroundColor Yellow
    Write-Host "Installe Rust via https://rustup.rs, puis relance." -ForegroundColor Yellow
    if ($LogPath) { Stop-Transcript | Out-Null }
    pause
    exit 1
}

Write-Host "Démarrage infra..." -ForegroundColor Cyan
if (Test-Path (Join-Path $root "docker-min.zip")) {
    Remove-Item (Join-Path $root "docker-min.zip") -Force -ErrorAction SilentlyContinue
}
docker compose up -d

Write-Host "Build services (release)..." -ForegroundColor Cyan
cargo build --release -p ember-api -p ember-ingest -p ember-worker

Write-Host "Démarrage services..." -ForegroundColor Cyan
Start-Process "./target/release/ember-ingest.exe" -WorkingDirectory $root
Start-Process "./target/release/ember-worker.exe" -WorkingDirectory $root
Start-Process "./target/release/ember-api.exe" -WorkingDirectory $root

Start-Sleep -Seconds 2
if (-not $NoBrowser) {
    Start-Process "http://localhost:3002/app"
}

Write-Host "EMBER est lancé. UI: http://localhost:3002/app" -ForegroundColor Green
if ($LogPath) { Stop-Transcript | Out-Null }
pause
