//! yogfile-mcp — le serveur MCP stdio (JSON-RPC 2.0, un message par
//! ligne) : le binaire qu'un client MCP lance sur la machine de
//! l'agent. L'identité (numéro de compte à 16 chiffres) vit dans un
//! petit état local (`~/.config/yogfile/mcp.json`), créée
//! automatiquement au premier besoin : un agent se provisionne sans
//! aucun humain dans la boucle. C'est le produit.

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
