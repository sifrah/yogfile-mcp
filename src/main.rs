//! yogfile-mcp — le serveur MCP stdio (JSON-RPC 2.0, un message par
//! ligne) : le binaire qu'un client MCP lance sur la machine de
//! l'agent. L'identité et l'autorisation révocable de cet appareil
//! vivent dans `~/.config/yogfile/mcp.json`. `yogfile-mcp auth`
//! enrôle une fois un compte protégé par MFA sans mettre ses secrets
//! dans l'historique du shell.

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use yogfile_mcp::{handle, ApiClient};

#[tokio::main]
async fn main() -> Result<()> {
    // Le défaut est la prod : un agent qui installe le binaire doit marcher
    // sans rien configurer. `YOGFILE_API=http://127.0.0.1:8081` en dev.
    let api = std::env::var("YOGFILE_API").unwrap_or_else(|_| "https://api.yogfile.com".into());
    let web = std::env::var("YOGFILE_WEB").unwrap_or_else(|_| "https://yogfile.com".into());
    let state_path = std::env::var("YOGFILE_MCP_STATE").unwrap_or_else(|_| {
        format!(
            "{}/.config/yogfile/mcp.json",
            std::env::var("HOME").unwrap_or_else(|_| ".".into())
        )
    });
    let mut client = ApiClient::new(api, web, state_path);

    if std::env::args().nth(1).as_deref() == Some("auth") {
        let number = rpassword::prompt_password("Yogfile account number (input hidden): ")?;
        if let Some(challenge) = client.begin_device_authorization(&number).await? {
            let code =
                rpassword::prompt_password("Authenticator or recovery code (input hidden): ")?;
            client
                .complete_device_authorization(&number, &challenge, &code)
                .await?;
        }
        let suffix: String = number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        println!("Yogfile MCP is authorized for the account ending in {suffix}.");
        return Ok(());
    }

    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // une ligne illisible ne tue pas la session
        };
        if let Some(resp) = handle(&mut client, &msg).await {
            let mut out = serde_json::to_vec(&resp)?;
            out.push(b'\n');
            stdout.write_all(&out).await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
