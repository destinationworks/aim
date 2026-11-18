use std::path::{Path, PathBuf};

use aim_proto::names::check_name;
use aim_server::auth::{generate_token, hash_token_hex};
use aim_server::certs::{init_ca, init_server_cert};
use aim_server::config::{KeyEntry, ServerConfig};
use aim_server::serve_with_config_path;
use clap::{Args, Parser, Subcommand};
use serde_json::json;

#[derive(Parser)]
#[command(name = "aim-server", about = "AIM (AI Messages) HTTPS hub server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the AIM HTTPS hub server
    Serve {
        #[arg(long, default_value = "/etc/aim/server.toml")]
        config: PathBuf,
    },
    /// Generate a private LAN Certificate Authority (ca.crt + 0600 ca.key)
    InitCa(InitCaArgs),
    /// Issue a server certificate signed by the private CA
    InitCert(InitCertArgs),
    /// Write a default server.toml
    InitConfig(InitConfigArgs),
    /// Generate a new bearer key for one computer and record its SHA-256 hash in server.toml
    Keygen(KeygenArgs),
    /// Disable all keys belonging to a host in server.toml
    Revoke {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        host: String,
    },
    /// List configured hosts and key hashes (never prints raw keys)
    ListKeys {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Args)]
struct InitCaArgs {
    #[arg(long)]
    ca_cert: PathBuf,
    #[arg(long)]
    ca_key: PathBuf,
    #[arg(long, default_value = "AIM Private LAN CA")]
    cn: String,
    #[arg(long, default_value_t = 3650)]
    days: u32,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct InitCertArgs {
    #[arg(long)]
    ca_cert: PathBuf,
    #[arg(long)]
    ca_key: PathBuf,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    /// DNS names or IP addresses for SANs (e.g. --san aim.example.internal --san 10.0.0.10)
    #[arg(long = "san", required = true)]
    sans: Vec<String>,
    #[arg(long, default_value_t = 398)]
    days: u32,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct InitConfigArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long, default_value = "0.0.0.0:11460")]
    listen: String,
    #[arg(long, default_value = "/aim")]
    base_path: String,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    tls_cert: PathBuf,
    #[arg(long)]
    tls_key: PathBuf,
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct KeygenArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    host: String,
    /// Write the generated token directly to a 0600 file instead of printing it to stdout
    #[arg(long)]
    out_key: Option<PathBuf>,
    #[arg(long)]
    force: bool,
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.command {
        Command::Serve { config } => run_serve(&config),
        Command::InitCa(args) => {
            init_ca(&args.ca_cert, &args.ca_key, &args.cn, args.days, args.force).map(|()| {
                println!(
                    "{}",
                    json!({
                        "ca_cert": args.ca_cert.display().to_string(),
                        "ca_key": args.ca_key.display().to_string(),
                    })
                );
            })
        }
        Command::InitCert(args) => init_server_cert(
            &args.ca_cert,
            &args.ca_key,
            &args.cert,
            &args.key,
            &args.sans,
            args.days,
            args.force,
        )
        .map(|()| {
            println!(
                "{}",
                json!({
                    "cert": args.cert.display().to_string(),
                    "key": args.key.display().to_string(),
                    "sans": args.sans,
                })
            );
        }),
        Command::InitConfig(args) => run_init_config(args),
        Command::Keygen(args) => run_keygen(args),
        Command::Revoke { config, host } => run_revoke(&config, &host),
        Command::ListKeys { config } => run_list_keys(&config),
    };

    if let Err(err) = res {
        eprintln!("aim-server: error: {err}");
        std::process::exit(1);
    }
}

fn run_serve(config_path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }

    let cfg = ServerConfig::load(config_path)?;
    let addr = cfg.listen_addr()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed creating async runtime: {e}"))?;
    rt.block_on(serve_with_config_path(cfg, addr, config_path.to_path_buf()))
}

fn run_init_config(args: InitConfigArgs) -> Result<(), String> {
    let mut cfg = ServerConfig::defaults_for(args.data_dir, args.tls_cert, args.tls_key);
    cfg.listen = args.listen;
    cfg.base_path = aim_server::config::normalize_base_path(&args.base_path)?;
    cfg.save_atomic(&args.config, args.force)?;
    println!("{}", json!({ "config": args.config.display().to_string() }));
    Ok(())
}

fn run_keygen(args: KeygenArgs) -> Result<(), String> {
    check_name("host", &args.host)?;

    // Lock around config modification
    let lock_path = args.config.with_extension("lock");
    let _lock = aim_fs::lock_file_exclusive(&lock_path)
        .map_err(|e| format!("cannot acquire config lock: {e}"))?;

    let mut cfg = ServerConfig::load(&args.config)?;
    let token = generate_token();
    let sha256 = hash_token_hex(&token);
    cfg.keys.push(KeyEntry {
        host: args.host.clone(),
        sha256: sha256.clone(),
        enabled: true,
    });
    cfg.save_atomic(&args.config, true)?;

    if let Some(out) = args.out_key {
        aim_fs::write_private_atomic(&out, format!("{token}\n").as_bytes(), args.force)?;
        println!(
            "{}",
            json!({
                "host": args.host,
                "sha256": sha256,
                "key_file": out.display().to_string(),
                "reload_hint": "send SIGHUP to aim-server or restart to apply changes"
            })
        );
    } else {
        println!(
            "{}",
            json!({
                "host": args.host,
                "sha256": sha256,
                "token": token,
                "reload_hint": "send SIGHUP to aim-server or restart to apply changes"
            })
        );
    }
    Ok(())
}

fn run_revoke(config_path: &Path, host: &str) -> Result<(), String> {
    check_name("host", host)?;

    let lock_path = config_path.with_extension("lock");
    let _lock = aim_fs::lock_file_exclusive(&lock_path)
        .map_err(|e| format!("cannot acquire config lock: {e}"))?;

    let mut cfg = ServerConfig::load(config_path)?;
    let mut changed = 0usize;
    for entry in &mut cfg.keys {
        if entry.host == host && entry.enabled {
            entry.enabled = false;
            changed += 1;
        }
    }
    cfg.save_atomic(config_path, true)?;
    println!(
        "{}",
        json!({
            "host": host,
            "revoked": changed,
            "reload_hint": "send SIGHUP to aim-server or restart to apply changes"
        })
    );
    Ok(())
}

fn run_list_keys(config_path: &Path) -> Result<(), String> {
    let cfg = ServerConfig::load(config_path)?;
    let rows: Vec<_> = cfg
        .keys
        .iter()
        .map(|k| json!({ "host": k.host, "sha256_prefix": &k.sha256[..12], "enabled": k.enabled }))
        .collect();
    println!("{}", json!({ "keys": rows }));
    Ok(())
}
