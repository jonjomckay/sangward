//! `keyward-testkit`: harness helper built only with `--features test-support`.
//!
//! Passwords are read from environment variables named by `--password-env`
//! so they never appear in process listings.

use clap::{Parser, Subcommand};
use keyward_core::api::{ApiClient, Endpoints};
use keyward_core::crypto::Kdf;
use keyward_core::test_support as ts;

#[derive(Parser)]
#[command(about = "keyward test harness helper (test-only)")]
struct Cli {
    /// Server base URL.
    #[arg(long, env = "KW_VW_URL")]
    server: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register an account with keyward's own crypto.
    Register {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_env: String,
        #[arg(long, value_parser = ["pbkdf2", "argon2id"])]
        kdf: String,
    },
    /// Enable authenticator 2FA; prints the base32 secret.
    EnableTotp {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_env: String,
    },
    /// Create an organization; prints `{"org_id":..,"collection_id":..}`.
    CreateOrg {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_env: String,
        #[arg(long)]
        totp_secret: Option<String>,
        #[arg(long)]
        name: String,
    },
    /// Print the current TOTP code for a seed (base32 or otpauth URI).
    Totp { secret: String },
    /// Dump the encrypted account material (prelogin KDF, protected key, raw sync) as JSON.
    DumpSync {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password_env: String,
        #[arg(long)]
        totp_secret: Option<String>,
    },
}

fn password(var: &str) -> Result<String, String> {
    std::env::var(var).map_err(|_| format!("environment variable {var} is not set"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("keyward-testkit: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    if let Cmd::Totp { secret } = &cli.cmd {
        println!("{}", ts::current_totp(secret).map_err(|e| e.to_string())?);
        return Ok(());
    }
    let endpoints =
        Endpoints::resolve(&cli.server, None, None, false).map_err(|e| e.to_string())?;
    let api = ApiClient::new(endpoints).map_err(|e| e.to_string())?;
    match cli.cmd {
        Cmd::Register {
            email,
            password_env,
            kdf,
        } => {
            let kdf = match kdf.as_str() {
                // Vaultwarden's minimum is 100k; keep the harness fast but realistic.
                "pbkdf2" => Kdf::Pbkdf2 {
                    iterations: 100_000,
                },
                _ => Kdf::Argon2id {
                    iterations: 3,
                    memory_mib: 64,
                    parallelism: 4,
                },
            };
            ts::register(&api, &email, &password(&password_env)?, kdf)
                .await
                .map_err(|e| e.to_string())?;
            eprintln!("registered {email}");
        }
        Cmd::EnableTotp {
            email,
            password_env,
        } => {
            let s = ts::enable_totp(&api, &email, &password(&password_env)?)
                .await
                .map_err(|e| e.to_string())?;
            println!("{s}");
        }
        Cmd::CreateOrg {
            email,
            password_env,
            totp_secret,
            name,
        } => {
            let (org, coll) = ts::create_org(
                &api,
                &email,
                &password(&password_env)?,
                totp_secret.as_deref(),
                &name,
            )
            .await
            .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({ "org_id": org, "collection_id": coll })
            );
        }
        Cmd::DumpSync {
            email,
            password_env,
            totp_secret,
        } => {
            use secrecy::ExposeSecret;
            let kdf = api.prelogin(&email).await.map_err(|e| e.to_string())?;
            let (tokens, _) = ts::login(
                &api,
                &email,
                &password(&password_env)?,
                totp_secret.as_deref(),
            )
            .await
            .map_err(|e| e.to_string())?;
            let (_, raw) = api
                .sync(tokens.access_token.expose_secret())
                .await
                .map_err(|e| e.to_string())?;
            let out = serde_json::json!({ "email": email, "kdf": kdf, "protected_key": tokens.key, "sync": raw });
            println!(
                "{}",
                serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
            );
        }
        Cmd::Totp { .. } => unreachable!(),
    }
    Ok(())
}
