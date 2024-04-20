mod sig;

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Ok};
use clap::{command, Parser, Subcommand};
use serde_json::json;
use sig::instance::JwtHeader;

use crate::sig::instance::SigInstanceCollection;

/// jwt is a command tool to sign or verify JWT (JSON WEB TOKEN)
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    subcommand: SubCommand,

    #[arg(short, long, default_value = "./secret_conf.json")]
    config_path: String,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Sign JWT
    Sign {
        #[arg(long)]
        sub: String,

        #[arg(long)]
        aud: String,

        #[arg(long)]
        exp: String,
    },

    /// Verify JWT
    Verify {
        #[arg(short, long)]
        token: String,
    },
}

fn main() -> anyhow::Result<()> {
    let c = Cli::parse();
    if let Err(e) = run_actual(c) {
        eprintln!("Error: {:?}", e);
    }
    Ok(())
}

fn run_actual(c: Cli) -> anyhow::Result<()> {
    let sig_ins = SigInstanceCollection::create_from_path(&c.config_path)?;
    match &c.subcommand {
        SubCommand::Sign { sub, aud, exp } => {
            let payload = json!(
                {
                    "sub":sub,
                    "aud":aud,
                    "exp":call_exp_ts(exp)?
                }
            );
            let default_header = JwtHeader {
                alg: "HS256".to_string(),
                typ: "JWT".to_string(),
            };
            let token = sig_ins.signature(&default_header, &payload)?;
            println!("Generated token: {}", token);
        }
        SubCommand::Verify { token } => {
            let (_h, p) = sig_ins.check(token.as_str())?;
            println!(
                "Valid signature, payload is: {}",
                serde_json::to_string_pretty(&p)?
            );
        }
    }
    Ok(())
}

// calculate expired ts
fn call_exp_ts(exp: &str) -> anyhow::Result<u64> {
    let (amount, unit) = exp.split_at(exp.len() - 1);
    let amount_s: u64 = amount.parse()?;
    let shift = match unit {
        "d" => amount_s * 3600 * 24,
        "h" => amount_s * 3600,
        "mi" => amount_s * 60,
        "s" => amount_s,
        _ => {
            bail!(
                "unsupported unit: {}, only support 'd','h','mi' or 's'",
                unit
            );
        }
    };
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + shift)
}
