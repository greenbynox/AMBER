use std::fs;
use std::io::Write;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use sysinfo::{System, SystemExt};

fn main() {
    let root = resolve_root().unwrap_or_else(|| {
        eprintln!("Impossible de localiser la racine du projet.");
        std::process::exit(1);
    });

    ensure_env_file(&root);
    dotenvy::dotenv().ok();

    let command = std::env::args().nth(1).unwrap_or_else(|| "start".to_string());
    match command.as_str() {
        "start" => start_launcher(&root, true),
        "stop" => stop_launcher(&root),
        "status" => status_launcher(&root),
        "update" => update_launcher(&root),
        _ => print_usage(),
    }
}

fn resolve_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin_dir = exe.parent()?; // target/release
    let maybe_target = bin_dir.parent()?; // target (dev) or package root (dist)
    if bin_dir.ends_with("release") && maybe_target.ends_with("target") {
        return Some(maybe_target.parent()?.to_path_buf());
    }
    Some(maybe_target.to_path_buf())
}

fn ensure_env_file(root: &Path) {
    let env_path = root.join(".env");
    if env_path.exists() {
        return;
    }

    let example_path = root.join(".env.example");
    if example_path.exists() {
        if let Ok(content) = fs::read_to_string(&example_path) {
            let _ = fs::write(&env_path, content);
            return;
        }
    }

    let placeholder = "DATABASE_URL=postgres://ember:ember@localhost:5432/ember\nEMBER_SECRET=change_me\nEMBER_JWT_SECRET=change_me_jwt\nEMBER_SECRETS_KEY=BASE64_32_BYTES\n";
    let _ = fs::write(&env_path, placeholder);
}

fn preflight_database() -> bool {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_default();
    if database_url.trim().is_empty() {
        return false;
    }

    let (host, port) = parse_database_host_port(&database_url).unwrap_or(("localhost".to_string(), 5432));
    let addr = format!("{}:{}", host, port);
    let timeout = Duration::from_secs(2);

    let socket = addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());

    match socket {
        Some(sock) => TcpStream::connect_timeout(&sock, timeout).is_ok(),
        None => false,
    }
}

fn parse_database_host_port(url: &str) -> Option<(String, u16)> {
    let after_scheme = url.split("//").nth(1)?;
    let host_part = after_scheme.split('@').nth(1).unwrap_or(after_scheme);
    let host_port = host_part.split('/').next().unwrap_or(host_part);
    let mut parts = host_port.split(':');
    let host = parts.next()?.trim();
    if host.is_empty() {
        return None;
    }
    let port = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(5432);
    Some((host.to_string(), port))
}

fn docker_available() -> bool {
    Command::new("docker").arg("--version").output().is_ok()
}

fn start_launcher(root: &Path, open_ui: bool) {
    print_system_checks();
    maybe_update_repo(root);

    if !ensure_docker_available() {
        eprintln!("Docker Desktop indisponible.");
        std::process::exit(1);
    }

    if !start_docker_daemon() {
        eprintln!("Impossible de démarrer Docker Desktop.");
        std::process::exit(1);
    }

    if !start_infra(root) {
        eprintln!("Docker compose a échoué.");
        std::process::exit(1);
    }

    if !wait_for_api() {
        eprintln!("API non disponible.");
        std::process::exit(1);
    }

    create_desktop_shortcut(root);

    if open_ui {
        let url = if port_open(3000) {
            "http://localhost:3000"
        } else {
            "http://localhost:3002/app"
        };
        open_browser(url);
    }
}

fn stop_launcher(root: &Path) {
    println!("Arrêt EMBER...");
    let _ = Command::new("docker")
        .current_dir(root)
        .args(["compose", "down"])
        .status();
}

fn status_launcher(root: &Path) {
    let _ = Command::new("docker")
        .current_dir(root)
        .args(["compose", "ps"])
        .status();
}

fn update_launcher(root: &Path) {
    maybe_update_repo(root);
    let _ = Command::new("docker")
        .current_dir(root)
        .args(["compose", "pull"])
        .status();
    let _ = Command::new("docker")
        .current_dir(root)
        .args(["compose", "build"])
        .status();
    start_launcher(root, true);
}

fn ensure_docker_available() -> bool {
    if docker_available() {
        return true;
    }

    if cfg!(target_os = "windows") {
        return install_docker_desktop_windows();
    }

    eprintln!("Docker n'est pas installé.");
    false
}

fn install_docker_desktop_windows() -> bool {
    let arch = std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default().to_uppercase();
    let url = if arch.contains("ARM") {
        "https://desktop.docker.com/win/main/arm64/Docker%20Desktop%20Installer.exe"
    } else {
        "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    };

    let installer = std::env::temp_dir().join("DockerDesktopInstaller.exe");
    let installer_str = installer.to_string_lossy().to_string();

    let download = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{}' -OutFile '{}'",
                url, installer_str
            ),
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if !download {
        eprintln!("Téléchargement Docker Desktop échoué.");
        return false;
    }

    let install_quiet = Command::new(&installer)
        .args(["install", "--quiet"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if !install_quiet {
        let install_fallback = Command::new(&installer)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !install_fallback {
            eprintln!("Installation Docker Desktop échouée.");
            return false;
        }
    }

    true
}

fn start_docker_daemon() -> bool {
    if docker_ready() {
        return true;
    }

    if cfg!(target_os = "windows") {
        let docker_exe = PathBuf::from(r"C:\Program Files\Docker\Docker\Docker Desktop.exe");
        if docker_exe.exists() {
            let _ = Command::new(docker_exe).spawn();
        }
    }

    let mut waited = 0;
    while waited < 120 {
        if docker_ready() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
        waited += 2;
    }

    false
}

fn docker_ready() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn start_infra(root: &Path) -> bool {
    Command::new("docker")
        .current_dir(root)
        .args(["compose", "up", "-d"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_for_api() -> bool {
    let mut waited = 0;
    while waited < 90 {
        if healthcheck_api() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
        waited += 2;
    }
    false
}

fn maybe_update_repo(root: &Path) {
    let git_dir = root.join(".git");
    if !git_dir.exists() {
        return;
    }

    if !internet_available() {
        println!("Pas d'accès internet, mise à jour ignorée.");
        return;
    }

    if Command::new("git").arg("--version").output().is_err() {
        return;
    }

    println!("Vérification des mises à jour...");

    let fetch_ok = Command::new("git")
        .current_dir(root)
        .args(["fetch", "--quiet"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if !fetch_ok {
        println!("Mise à jour ignorée (git fetch échoué)." );
        return;
    }

    let head = git_rev(root, "HEAD");
    let upstream = git_rev(root, "@{u}");

    if let (Some(head), Some(upstream)) = (head, upstream) {
        if head != upstream {
            println!("Mise à jour disponible, application...");
            let pulled = Command::new("git")
                .current_dir(root)
                .args(["pull", "--rebase", "--autostash"])
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
            if pulled {
                println!("Mise à jour appliquée.");
            } else {
                println!("Mise à jour échouée.");
            }
        }
    }
}

fn git_rev(root: &Path, rev: &str) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", rev])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn internet_available() -> bool {
    let timeout = Duration::from_secs(2);
    let addr = ("github.com", 443)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());

    match addr {
        Some(sock) => TcpStream::connect_timeout(&sock, timeout).is_ok(),
        None => false,
    }
}

fn spawn_service(binary: &Path, root: &Path, label: &str) -> Child {
    println!("→ {}", label);
    Command::new(binary)
        .current_dir(root)
        .spawn()
        .unwrap_or_else(|err| {
            eprintln!("Impossible de démarrer {}: {}", label, err);
            std::process::exit(1);
        })
}

fn exe_name(base: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{}.exe", base)
    } else {
        base.to_string()
    }
}

fn open_browser(url: &str) {
    if cfg!(target_os = "windows") {
        let _ = Command::new("cmd").args(["/C", "start", "", url]).spawn();
    } else if cfg!(target_os = "macos") {
        let _ = Command::new("open").arg(url).spawn();
    } else {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

fn create_desktop_shortcut(root: &Path) {
    if !cfg!(target_os = "windows") {
        create_unix_shortcut(root);
        return;
    }

    let exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return,
    };
    let exe_path_str = exe_path.to_string_lossy().to_string();
    let work_dir = root.to_string_lossy().to_string();

    let icon_path = root.join("assets").join("amber.ico");
    let icon_path_str = icon_path.to_string_lossy().to_string();
    if let Some(parent) = icon_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    if !icon_path.exists() {
        let _ = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$iconPath='{}'; Add-Type -AssemblyName System.Drawing; $bmp = New-Object System.Drawing.Bitmap 256,256; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.Clear([System.Drawing.Color]::FromArgb(15,23,42)); $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(56,189,248)); $g.FillEllipse($brush,16,16,224,224); $font = New-Object System.Drawing.Font('Segoe UI',120,[System.Drawing.FontStyle]::Bold); $g.DrawString('A',$font,[System.Drawing.Brushes]::White,60,40); $icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon()); $fs = New-Object System.IO.FileStream($iconPath,'Create'); $icon.Save($fs); $fs.Close(); $g.Dispose(); $bmp.Dispose();",
                    icon_path_str.replace("'", "''")
                ),
            ])
            .status();
    }

    let icon_target = if icon_path.exists() {
        icon_path_str.clone()
    } else {
        exe_path_str.clone()
    };

    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('$env:USERPROFILE\\Desktop\\EMBER.lnk'); $Shortcut.TargetPath = '{}'; $Shortcut.WorkingDirectory = '{}'; $Shortcut.IconLocation = '{}'; $Shortcut.Save();",
                exe_path_str.replace("'", "''"),
                work_dir.replace("'", "''"),
                icon_target.replace("'", "''"),
            ),
        ])
        .status();
}

fn create_unix_shortcut(root: &Path) {
    let exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return,
    };

    let home = std::env::var("HOME").ok();
    if cfg!(target_os = "linux") {
        if let Some(home) = home.as_deref() {
            let app_dir = PathBuf::from(home).join(".local/share/applications");
            let desktop_dir = PathBuf::from(home).join("Desktop");
            let _ = fs::create_dir_all(&app_dir);

            let desktop_file = app_dir.join("amber.desktop");
            let content = format!(
                "[Desktop Entry]\nType=Application\nName=EMBER\nExec=\"{}\" start\nIcon={}\nTerminal=false\n",
                exe_path.display(),
                exe_path.display()
            );
            let _ = fs::write(&desktop_file, content);
            let _ = fs::copy(&desktop_file, desktop_dir.join("EMBER.desktop"));
        }
    }

    if cfg!(target_os = "macos") {
        if let Some(home) = home.as_deref() {
            let shortcut = PathBuf::from(home).join("Desktop").join("EMBER.command");
            let content = format!("#!/bin/bash\n\"{}\" start\n", exe_path.display());
            if fs::write(&shortcut, content).is_ok() {
                let _ = Command::new("chmod")
                    .args(["+x", shortcut.to_string_lossy().as_ref()])
                    .status();
            }
        }
    }
}

fn healthcheck_api() -> bool {
    let addr = ("127.0.0.1", 3002)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());

    let socket = match addr {
        Some(sock) => sock,
        None => return false,
    };

    if let Ok(mut stream) = TcpStream::connect_timeout(&socket, Duration::from_secs(2)) {
        let _ = stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        return true;
    }
    false
}

fn print_system_checks() {
    check_port_available(3002);
    check_port_available(3001);
    check_port_available(3000);

    let mut sys = System::new();
    sys.refresh_memory();
    let total_gb = sys.total_memory() as f64 / 1024.0 / 1024.0;
    if total_gb < 4.0 {
        eprintln!("Attention: RAM faible ({:.1} GB).", total_gb);
    }
}

fn check_port_available(port: u16) {
    if TcpListener::bind(("127.0.0.1", port)).is_err() {
        eprintln!("Port {} déjà utilisé.", port);
    }
}

fn port_open(port: u16) -> bool {
    let addr = ("127.0.0.1", port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());

    match addr {
        Some(sock) => TcpStream::connect_timeout(&sock, Duration::from_millis(500)).is_ok(),
        None => false,
    }
}

fn print_usage() {
    println!("Usage: ember-launcher [start|stop|status|update]");
}
