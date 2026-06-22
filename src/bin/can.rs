//! The `can` command-line utility for managing bare-metal/local secret stores securely.

use std::io::IsTerminal;
use std::io::{self, Write};

use anyhow::Result;
use clap::Parser;
use secrecy::ExposeSecret;
use tinny::{Actions, Can, Cli, prompt_passphrase, read_secret};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (mut can, is_new_file) = Can::open_or_create(cli.file)?;

    match cli.action {
        Actions::Create {
            pointer,
            length,
            generate,
        } => {
            can.validate_create(&pointer)?;
            let confirm_passphrase = is_new_file && io::stdin().is_terminal();
            let passphrase = prompt_passphrase(confirm_passphrase)?;
            can.unlock(&passphrase)?;
            let secret = read_secret(length, generate)?;
            can.create(&pointer, secret)?;
            can.save_atomic()?;
            println!("created {pointer}");
        }
        Actions::Read { pointer } => {
            can.validate_read(&pointer)?;
            let passphrase = prompt_passphrase(false)?;
            can.unlock(&passphrase)?;
            let secret = can.read(&pointer)?;
            io::stdout().write_all(secret.expose_secret())?;
            io::stdout().write_all(b"\n")?;
        }
        Actions::Update {
            pointer,
            length,
            generate,
        } => {
            can.validate_update(&pointer)?;
            let passphrase = prompt_passphrase(false)?;
            can.unlock(&passphrase)?;
            let secret = read_secret(length, generate)?;
            can.update(&pointer, secret)?;
            can.save_atomic()?;
            println!("updated {pointer}");
        }
        Actions::Delete { pointer } => {
            can.delete(&pointer)?;
            can.save_atomic()?;
            println!("deleted {pointer}");
        }
        Actions::List { pointer } => {
            let value = can.list(&pointer)?;
            serde_json::to_writer_pretty(io::stdout(), &value)?;
            io::stdout().write_all(b"\n")?;
        }
    }

    can.lock();
    Ok(())
}
