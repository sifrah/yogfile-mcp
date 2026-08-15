//! yogfile-mcp — Yogfile pour agents, en une ligne de config.
//!
//! Serveur MCP stdio (JSON-RPC 2.0, un message par ligne) exposant six
//! tools sur l'API Yogfile. Le tool `upload_file` fait le trajet
//! complet tout seul : BLAKE3 des octets (lié dans la signature du
//! grant), PUT streamé DIRECTEMENT sur la node Nauka que le geo-DNS
//! désigne, puis confirm — l'agent donne un chemin, il reçoit un lien
//! de partage qui expire.
//!
//! L'identité (numéro de compte à 16 chiffres) vit dans un petit état
//! local (`~/.config/yogfile/mcp.json`), créée automatiquement au
//! premier besoin : un agent se provisionne sans aucun humain dans la
//! boucle. C'est le produit.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOL_VERSION: &str = "2025-06-18";

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

/// Route un message JSON-RPC. Les notifications ne répondent rien.
async fn handle(client: &mut ApiClient, msg: &Value) -> Option<Value> {
    let method = msg.get("method")?.as_str()?;
    let id = msg.get("id").cloned();
    // Notification (pas d'id) : on absorbe sans répondre.
    id.as_ref()?;
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": msg["params"]["protocolVersion"]
                .as_str()
                .unwrap_or(PROTOCOL_VERSION),
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "yogfile", "version": env!("CARGO_PKG_VERSION") },
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_specs() })),
        "tools/call" => {
            let name = msg["params"]["name"].as_str().unwrap_or_default();
            let args = msg["params"]["arguments"].clone();
            match call_tool(client, name, args).await {
                Ok(text) => Ok(json!({
                    "content": [{ "type": "text", "text": text }],
                    "isError": false,
                })),
                // Une erreur de TOOL reste un succès JSON-RPC : c'est
                // l'agent qui doit la lire, pas le client MCP.
                Err(e) => Ok(json!({
                    "content": [{ "type": "text", "text": format!("error: {e:#}") }],
                    "isError": true,
                })),
            }
        }
        _ => Err(json!({ "code": -32601, "message": format!("unknown method {method}") })),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
    })
}

fn tool_specs() -> Value {
    json!([
        {
            "name": "create_account",
            "description": "Create a fresh anonymous Yogfile account and return its 16-digit \
                            number. You rarely need this: the other tools create an account by \
                            themselves on first use. Call it only when the user explicitly asks \
                            to start over with a new account. The number is saved locally and is \
                            the ONLY credential: if it is lost the account cannot be recovered, \
                            so show it to the user when it is created.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "create_box",
            "description": "Create a box and return its short public name (like x7k2p9). A box \
                            is a flat folder: files live in one, and its URL shows every file it \
                            holds. Use it to group several files under a single URL for someone. \
                            For a single file you do not need this, since upload_file will place \
                            it in a default box on its own.",
            "inputSchema": { "type": "object", "properties": {
                "private": { "type": "boolean", "description": "require a passphrase to see the file list; a passphrase is generated if you do not supply one" },
                "passphrase": { "type": "string" },
                "default_ttl_secs": { "type": "integer", "description": "default lifetime of files uploaded to this box (60..2592000)" }
            } }
        },
        {
            "name": "upload_file",
            "description": "Upload a local file and return a stable share URL to hand to the \
                            user. This is the main tool: use it whenever you have produced a \
                            file the user should be able to download, instead of describing a \
                            path they cannot reach. It does the content hash, the signed grant, \
                            the direct upload to the nearest node and the confirmation in one \
                            call. Pass `folder` to file it under a path like 'reports/2024/q3', \
                            which is how you keep a run's output organised instead of dumping \
                            everything at the root. Every file expires: 7 days by default, 30 at \
                            the most on the free plan. Tell the user when it expires along with \
                            the URL.",
            "inputSchema": { "type": "object", "properties": {
                "path": { "type": "string", "description": "local file path to read from" },
                "folder": { "type": "string", "description": "where to file it inside the box, as a path like 'reports/2024/q3'. Missing levels are created. Omit for the box root" },
                "box": { "type": "string", "description": "name of an existing box; omit to use a default box, which is created on first upload" },
                "name": { "type": "string", "description": "the name the recipient sees; omit to use the file's own name on disk" },
                "ttl_secs": { "type": "integer", "description": "how long the file lives, in seconds (60 to 2592000, i.e. one minute to 30 days). Omit for the box default of 7 days" }
            }, "required": ["path"] }
        },
        {
            "name": "create_folder",
            "description": "Create a folder inside a box and return its id. Give the full path \
                            from the box root, like 'reports/2024/q3'; every missing level is \
                            created in one call, and an existing path is returned as is rather \
                            than duplicated. Nesting is unlimited. You rarely need this on its \
                            own, since upload_file creates the path it is given.",
            "inputSchema": { "type": "object", "properties": {
                "path": { "type": "string", "description": "path from the box root, e.g. 'reports/2024/q3'" },
                "box": { "type": "string", "description": "box name; omit to use your default box" }
            }, "required": ["path"] }
        },
        {
            "name": "share_link",
            "description": "Mint a short-lived signed URL that starts the download immediately, \
                            with no page in between. Prefer the stable share URL returned by \
                            upload_file when handing something to a person: it keeps working, \
                            shows the file name and size, and can be previewed. Use this one for \
                            a machine that needs raw bytes, or when one click is one too many. \
                            It expires in 10 minutes by default.",
            "inputSchema": { "type": "object", "properties": {
                "file_id": { "type": "string" },
                "ttl_secs": { "type": "integer", "description": "how long the signed URL stays valid, in seconds (60 to 86400, default 600)" }
            }, "required": ["file_id"] }
        },
        {
            "name": "list_files",
            "description": "List boxes, their folder tree, and the live files in them shown at \
                            their full path. \
                            Call it to find the file_id that share_link and delete_file need, to \
                            check what is about to expire, or to see what another run left \
                            behind in a shared box.",
            "inputSchema": { "type": "object", "properties": {
                "box": { "type": "string", "description": "restrict to one box; omit to list every box you own" }
            } }
        },
        {
            "name": "delete_file",
            "description": "Delete a file immediately and irreversibly. Its share URL and every \
                            signed link pointing at it stop working at once. There is no undo and \
                            no recycle bin, so confirm with the user before calling it on \
                            anything you did not create in this session.",
            "inputSchema": { "type": "object", "properties": {
                "file_id": { "type": "string" }
            }, "required": ["file_id"] }
        }
    ])
}

async fn call_tool(client: &mut ApiClient, name: &str, args: Value) -> Result<String> {
    match name {
        "create_account" => client.create_account().await,
        "create_box" => client.create_box(&args).await,
        "create_folder" => client.create_folder(&args).await,
        "upload_file" => client.upload_file(&args).await,
        "share_link" => client.share_link(&args).await,
        "list_files" => client.list_files(&args).await,
        "delete_file" => client.delete_file(&args).await,
        other => Err(anyhow!("unknown tool {other}")),
    }
}

/// « dans 6 jours », « dans 3 heures ». Un modèle relaie cela tel
/// quel ; il ne peut rien faire d'un entier de dix chiffres.
fn relative_time(unix: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let d = unix - now;
    if d <= 0 {
        return "already past".into();
    }
    let (n, unit) = match d {
        _ if d < 3600 => (d / 60, "minute"),
        _ if d < 86_400 => (d / 3600, "hour"),
        _ if d < 2_592_000 => (d / 86_400, "day"),
        _ => (d / 2_592_000, "month"),
    };
    let n = n.max(1);
    format!("in {n} {unit}{}", if n == 1 { "" } else { "s" })
}

// ───────────────────────── le client API ─────────────────────────

struct ApiClient {
    base: String,
    /// La façade WEB, distincte de l'API : c'est elle qui sert la
    /// page d'un fichier, celle qu'un humain reçoit.
    web: String,
    http: reqwest::Client,
    state_path: String,
    number: Option<String>,
    token: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct LocalState {
    account_number: Option<String>,
}

impl ApiClient {
    fn new(base: String, web: String, state_path: String) -> Self {
        let number = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<LocalState>(&b).ok())
            .and_then(|s| s.account_number);
        Self {
            base: base.trim_end_matches('/').to_string(),
            web: web.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            state_path,
            number,
            token: None,
        }
    }

    fn save_number(&self, number: &str) {
        if let Some(dir) = std::path::Path::new(&self.state_path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let state = LocalState {
            account_number: Some(number.to_string()),
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&state) {
            let _ = std::fs::write(&self.state_path, bytes);
        }
    }

    /// Extrait `data` d'une réponse API, ou transforme `error` en
    /// message lisible par l'agent (code + message + hint).
    async fn unwrap_api(resp: reqwest::Response) -> Result<Value> {
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if let Some(err) = body.get("error") {
            let hint = err["hint"]
                .as_str()
                .map(|h| format!(" ({h})"))
                .unwrap_or_default();
            return Err(anyhow!(
                "{} [{}]{hint}",
                err["message"].as_str().unwrap_or("request refused"),
                err["code"].as_str().unwrap_or("unknown"),
            ));
        }
        if !status.is_success() {
            return Err(anyhow!("HTTP {status}"));
        }
        Ok(body["data"].clone())
    }

    async fn ensure_session(&mut self) -> Result<String> {
        if let Some(t) = &self.token {
            return Ok(t.clone());
        }
        if self.number.is_none() {
            // Auto-provisionnement : la promesse du produit.
            let data = Self::unwrap_api(
                self.http
                    .post(format!("{}/v2/accounts", self.base))
                    .send()
                    .await?,
            )
            .await?;
            let number = data["account_number"]
                .as_str()
                .context("no account_number in response")?
                .to_string();
            self.save_number(&number);
            self.number = Some(number);
        }
        let number = self.number.clone().unwrap();
        let data = Self::unwrap_api(
            self.http
                .post(format!("{}/v2/sessions", self.base))
                .json(&json!({ "account_number": number }))
                .send()
                .await?,
        )
        .await?;
        let token = data["token"].as_str().context("no token")?.to_string();
        self.token = Some(token.clone());
        Ok(token)
    }

    /// Requête authentifiée avec UNE nouvelle session en cas de 401
    /// (le JWT vit 24 h, le serveur MCP peut vivre plus longtemps).
    async fn authed(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        for attempt in 0..2 {
            let token = self.ensure_session().await?;
            let mut req = self
                .http
                .request(method.clone(), format!("{}{path}", self.base))
                .bearer_auth(&token);
            if let Some(b) = &body {
                req = req.json(b);
            }
            let resp = req.send().await?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                self.token = None;
                continue;
            }
            return Self::unwrap_api(resp).await;
        }
        unreachable!()
    }

    async fn create_account(&mut self) -> Result<String> {
        let data = Self::unwrap_api(
            self.http
                .post(format!("{}/v2/accounts", self.base))
                .send()
                .await?,
        )
        .await?;
        let number = data["account_number"]
            .as_str()
            .context("no account_number")?
            .to_string();
        self.save_number(&number);
        self.number = Some(number.clone());
        self.token = None;
        Ok(format!(
            "account created: {number}\nSTORE THIS NUMBER — it is the account, \
             there is no recovery. It is also saved in {} for this server's future calls.",
            self.state_path
        ))
    }

    async fn create_box(&mut self, args: &Value) -> Result<String> {
        let mut body = serde_json::Map::new();
        if let Some(p) = args["private"].as_bool() {
            body.insert("private".into(), json!(p));
        }
        if let Some(p) = args["passphrase"].as_str() {
            body.insert("passphrase".into(), json!(p));
        }
        if let Some(t) = args["default_ttl_secs"].as_i64() {
            body.insert("default_ttl_secs".into(), json!(t));
        }
        let data = self
            .authed(
                reqwest::Method::POST,
                "/v2/boxes",
                Some(Value::Object(body)),
            )
            .await?;
        Ok(format!(
            "box created: {} (private: {})",
            data["name"].as_str().unwrap_or("?"),
            data["private"]
        ))
    }

    /// La box par défaut : la première du compte, créée au besoin.
    async fn default_box(&mut self) -> Result<String> {
        let boxes = self.authed(reqwest::Method::GET, "/v2/boxes", None).await?;
        if let Some(first) = boxes.as_array().and_then(|a| a.first()) {
            return Ok(first["name"].as_str().unwrap_or_default().to_string());
        }
        let data = self
            .authed(reqwest::Method::POST, "/v2/boxes", Some(json!({})))
            .await?;
        Ok(data["name"].as_str().unwrap_or_default().to_string())
    }

    async fn create_folder(&mut self, args: &Value) -> Result<String> {
        let path = args["path"].as_str().context("path is required")?;
        let box_name = match args["box"].as_str() {
            Some(b) => b.to_string(),
            None => self.default_box().await?,
        };
        let data = self
            .authed(
                reqwest::Method::POST,
                &format!("/v2/boxes/{box_name}/folders"),
                Some(json!({ "path": path })),
            )
            .await?;
        Ok(format!(
            "folder {} ready in box {box_name}\nfolder_id: {}",
            data["path"].as_str().unwrap_or(path),
            data["folder_id"].as_str().unwrap_or("?"),
        ))
    }

    async fn upload_file(&mut self, args: &Value) -> Result<String> {
        let path = args["path"].as_str().context("path is required")?;
        let meta = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("cannot read {path}"))?;
        if !meta.is_file() {
            return Err(anyhow!("{path} is not a file"));
        }
        let size = meta.len() as i64;
        let display_name = args["name"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| {
                std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".into())
            });
        let box_name = match args["box"].as_str() {
            Some(b) => b.to_string(),
            None => self.default_box().await?,
        };

        // 1. BLAKE3 en streaming : lié dans la signature du grant, la
        //    fenêtre de ±300 s ne vaut que pour CES octets.
        let mut hasher = blake3::Hasher::new();
        {
            use tokio::io::AsyncReadExt;
            let mut f = tokio::fs::File::open(path).await?;
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = f.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
        }
        let blake3_hex = hasher.finalize().to_hex().to_string();

        // 2. Le grant.
        let mut body = serde_json::Map::new();
        body.insert("name".into(), json!(display_name));
        body.insert("size".into(), json!(size));
        body.insert("blake3".into(), json!(blake3_hex));
        if let Some(t) = args["ttl_secs"].as_i64() {
            body.insert("ttl_secs".into(), json!(t));
        }
        if let Some(f) = args["folder"]
            .as_str()
            .map(str::trim)
            .filter(|f| !f.is_empty())
        {
            body.insert("folder".into(), json!(f));
        }
        let grant = self
            .authed(
                reqwest::Method::POST,
                &format!("/v2/boxes/{box_name}/uploads"),
                Some(Value::Object(body)),
            )
            .await?;
        let file_id = grant["file_id"].as_str().context("no file_id")?.to_string();
        let up_url = grant["upload"]["url"].as_str().context("no upload url")?;

        // 3. PUT streamé direct sur la node : les octets ne passent ni
        //    par l'API Yogfile ni par la RAM du serveur MCP.
        let file = tokio::fs::File::open(path).await?;
        let stream = tokio_util::io::ReaderStream::new(file);
        let mut req = self
            .http
            .put(up_url)
            .body(reqwest::Body::wrap_stream(stream));
        if let Some(headers) = grant["upload"]["headers"].as_object() {
            for (k, v) in headers {
                req = req.header(k.as_str(), v.as_str().unwrap_or_default());
            }
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!("node refused the upload: {status} {text}"));
        }
        let node_resp: Value = resp.json().await?;
        let hash = node_resp["hash"].as_str().context("no hash from node")?;

        // 4. Confirm : l'API vérifie sur la node et active.
        let confirmed = self
            .authed(
                reqwest::Method::POST,
                &format!("/v2/files/{file_id}/confirm"),
                Some(json!({ "hash": hash })),
            )
            .await?;
        let expires_at = confirmed["expires_at"].as_i64().unwrap_or(0);
        Ok(format!(
            "uploaded: {display_name} ({size} bytes) to box {box_name}\n\
             share this URL with the user: {}/f/{file_id}\n\
             expires: {} ({expires_at} unix)\n\
             file_id: {file_id}",
            self.web,
            relative_time(expires_at),
        ))
    }

    async fn share_link(&mut self, args: &Value) -> Result<String> {
        let file_id = args["file_id"].as_str().context("file_id is required")?;
        let mut body = serde_json::Map::new();
        if let Some(t) = args["ttl_secs"].as_i64() {
            body.insert("ttl_secs".into(), json!(t));
        }
        let data = self
            .authed(
                reqwest::Method::POST,
                &format!("/v2/files/{file_id}/links"),
                Some(Value::Object(body)),
            )
            .await?;
        Ok(format!(
            "direct link, downloads immediately, dies {}: {}\n\
             stable page to share with a person instead: {}/f/{file_id}",
            data["exp"]
                .as_i64()
                .map(relative_time)
                .unwrap_or_else(|| "soon".into()),
            data["url"].as_str().unwrap_or("?"),
            self.web,
        ))
    }

    async fn list_files(&mut self, args: &Value) -> Result<String> {
        let boxes: Vec<String> = match args["box"].as_str() {
            Some(b) => vec![b.to_string()],
            None => {
                let all = self.authed(reqwest::Method::GET, "/v2/boxes", None).await?;
                all.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|b| b["name"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default()
            }
        };
        if boxes.is_empty() {
            return Ok("no boxes yet. upload_file creates one automatically".into());
        }
        let mut out = String::new();
        for name in boxes {
            let bx = self
                .authed(reqwest::Method::GET, &format!("/v2/boxes/{name}"), None)
                .await?;
            out.push_str(&format!(
                "box {name}{}\n",
                if bx["private"].as_bool().unwrap_or(false) {
                    " (private)"
                } else {
                    ""
                }
            ));
            // Le chemin de chaque dossier, reconstruit en remontant
            // les parents : « f3a2… » ne dit rien à un modèle,
            // « reports/2024 » lui permet de raisonner.
            let empty = vec![];
            let folders = bx["folders"].as_array().unwrap_or(&empty);
            let path_of = |id: &str| -> String {
                let mut parts = Vec::new();
                let mut cur = Some(id.to_string());
                while let Some(c) = cur {
                    match folders
                        .iter()
                        .find(|f| f["id"].as_str() == Some(c.as_str()))
                    {
                        Some(f) => {
                            parts.push(f["name"].as_str().unwrap_or("?").to_string());
                            cur = f["parent_id"].as_str().map(str::to_string);
                        }
                        None => break,
                    }
                }
                parts.reverse();
                parts.join("/")
            };
            // Triés par CHEMIN : la base ordonne par nom, ce qui
            // entrelace les niveaux et rend l'arbre illisible.
            let mut paths: Vec<String> = folders
                .iter()
                .map(|f| path_of(f["id"].as_str().unwrap_or("")))
                .collect();
            paths.sort();
            for p in paths {
                out.push_str(&format!("  {p}/\n"));
            }
            match bx["files"].as_array().filter(|f| !f.is_empty()) {
                Some(files) => {
                    for f in files {
                        let dir = f["folder_id"]
                            .as_str()
                            .map(|id| format!("{}/", path_of(id)))
                            .unwrap_or_default();
                        out.push_str(&format!(
                            "  {}: {dir}{} ({} bytes, expires {})\n",
                            f["id"].as_str().unwrap_or("?"),
                            f["name"].as_str().unwrap_or("?"),
                            f["size"],
                            relative_time(f["expires_at"].as_i64().unwrap_or(0)),
                        ));
                    }
                }
                None if folders.is_empty() => out.push_str("  (empty)\n"),
                None => {}
            }
        }
        Ok(out)
    }

    async fn delete_file(&mut self, args: &Value) -> Result<String> {
        let file_id = args["file_id"].as_str().context("file_id is required")?;
        self.authed(
            reqwest::Method::DELETE,
            &format!("/v2/files/{file_id}"),
            None,
        )
        .await?;
        Ok(format!(
            "deleted {file_id}. Its file page and every link pointing at it are dead"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ApiClient {
        ApiClient::new(
            "http://127.0.0.1:1".into(),
            "https://yogfile.com".into(),
            "/tmp/never-written.json".into(),
        )
    }

    #[test]
    fn expiries_are_readable_by_whoever_relays_them() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(relative_time(now + 604_800), "in 7 days");
        assert_eq!(relative_time(now + 3600), "in 1 hour");
        assert_eq!(relative_time(now + 90), "in 1 minute");
        assert_eq!(relative_time(now - 10), "already past");
    }

    #[tokio::test]
    async fn initialize_and_tools_list_answer_without_network() {
        let mut c = client();
        let resp = handle(
            &mut c,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": { "protocolVersion": "2025-06-18",
                            "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } }
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "yogfile");
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");

        let resp = handle(
            &mut c,
            &serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        )
        .await
        .unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        for expected in [
            "create_account",
            "create_box",
            "create_folder",
            "upload_file",
            "share_link",
            "list_files",
            "delete_file",
        ] {
            assert!(names.contains(&expected), "{expected} manquant: {names:?}");
        }
    }

    #[tokio::test]
    async fn notifications_get_no_answer_and_unknown_methods_error() {
        let mut c = client();
        // Notification (pas d'id) : silence.
        let resp = handle(
            &mut c,
            &serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
        assert!(resp.is_none());
        // Méthode inconnue : erreur JSON-RPC -32601.
        let resp = handle(
            &mut c,
            &serde_json::json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" }),
        )
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn tool_errors_are_results_not_rpc_errors() {
        let mut c = client();
        // upload_file sans path : erreur de tool, PAS d'erreur JSON-RPC.
        let resp = handle(
            &mut c,
            &serde_json::json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": { "name": "upload_file", "arguments": {} } }),
        )
        .await
        .unwrap();
        assert!(resp["error"].is_null());
        assert_eq!(resp["result"]["isError"], true);
        assert!(resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("path"));
    }
}
