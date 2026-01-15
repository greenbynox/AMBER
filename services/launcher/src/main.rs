use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

fn main() {
    let root = resolve_repo_root().unwrap_or_else(|| {
        eprintln!("Impossible de localiser la racine du projet.");
        std::process::exit(1);
    });

    ensure_env_file(&root);
    dotenvy::dotenv().ok();

    if !preflight_database() {
        eprintln!("PostgreSQL indisponible. EMBER ne peut pas démarrer.");
        if docker_available() {
            eprintln!("Lancez l'infra: docker compose up -d");
        } else {
            eprintln!("Installez Docker Desktop (recommandé) ou PostgreSQL local.");
        }
        eprintln!("Ensuite relancez ember-launcher.exe");
        std::process::exit(1);
    }

    let bin_dir = resolve_bin_dir().unwrap_or_else(|| {
        eprintln!("Impossible de localiser le dossier des binaires.");
        std::process::exit(1);
    });

    let api = bin_dir.join(exe_name("ember-api"));
    let ingest = bin_dir.join(exe_name("ember-ingest"));
    let worker = bin_dir.join(exe_name("ember-worker"));

    for bin in [&api, &ingest, &worker] {
        if !bin.exists() {
            eprintln!("Binaire manquant: {}", bin.display());
            eprintln!("Build requis: cargo build --release -p ember-api -p ember-ingest -p ember-worker -p ember-launcher");
            std::process::exit(1);
        }
    }

    println!("Démarrage EMBER...");

    let mut children = Vec::new();
    children.push(spawn_service(&api, &root, "API (3002)"));
    children.push(spawn_service(&ingest, &root, "Ingest (3001)"));
    children.push(spawn_service(&worker, &root, "Worker"));

    std::thread::sleep(Duration::from_secs(1));
    open_browser("http://localhost:3002/app");

    println!("EMBER est lancé. Fermez cette fenêtre pour arrêter les services.");

    wait_for_exit(children);
}

fn resolve_repo_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin_dir = exe.parent()?; // target/release
    let target_dir = bin_dir.parent()?; // target
    let root = target_dir.parent()?; // repo
    Some(root.to_path_buf())
}

fn resolve_bin_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin_dir = exe.parent()?;
    Some(bin_dir.to_path_buf())
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

fn wait_for_exit(mut children: Vec<Child>) {
    loop {
        for idx in (0..children.len()).rev() {
            if let Ok(Some(status)) = children[idx].try_wait() {
                eprintln!("Service arrêté (status: {}). Fermeture...", status);
                children.remove(idx);
            }
        }

        if children.is_empty() {
            break;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}
