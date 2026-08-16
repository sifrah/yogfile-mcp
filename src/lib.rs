//! yogfile-mcp — Yogfile pour agents.
//!
//! Le cœur partagé par les deux transports : le client de l'API
//! Yogfile, les sept tools et le routage JSON-RPC. `main.rs` l'expose
//! en stdio (binaire local, un fichier de config chez le client) ;
//! `bin/remote.rs` en Streamable HTTP + OAuth (le connecteur
//! `mcp.yogfile.com`, zéro installation). Le tool `upload_file` fait le trajet
//! complet tout seul : BLAKE3 des octets (lié dans la signature du
//! grant), PUT streamé DIRECTEMENT sur la node Nauka que le geo-DNS
//! désigne, puis confirm — l'agent donne un chemin, il reçoit un lien
//! de partage court, lui, qui expire.
//!
//! L'identité (numéro de compte à 16 chiffres) vit dans un petit état
//! local (`~/.config/yogfile/mcp.json`), créée automatiquement au
//! premier besoin : un agent se provisionne sans aucun humain dans la
//! boucle. C'est le produit.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Route un message JSON-RPC. Les notifications ne répondent rien.
pub async fn handle(client: &mut ApiClient, msg: &Value) -> Option<Value> {
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
        "tools/list" => Ok(json!({ "tools": tool_specs(client.remote) })),
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

/// Les tools. En remote, `create_account` disparaît (l'identité est
/// celle du connecteur OAuth) et `upload_file` prend un contenu ou une
/// URL au lieu d'un chemin : un serveur hébergé ne voit pas le disque
/// de l'agent.
pub fn tool_specs(remote: bool) -> Value {
    let mut tools = tool_specs_local();
    if remote {
        let arr = tools.as_array_mut().unwrap();
        arr.retain(|t| t["name"] != "create_account");
        for t in arr.iter_mut() {
            if t["name"] == "upload_file" {
                *t = upload_spec_remote();
            }
        }
    }
    tools
}

fn upload_spec_remote() -> Value {
    json!({
        "name": "upload_file",
        "title": "Upload a file",
        "annotations": { "title": "Upload a file", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": true },
        "description": "Upload a file and return a stable share URL to hand to the user. \
                        This is the main tool: use it whenever you have produced something \
                        the user should be able to download or pass on — a report, code, \
                        data, an image — instead of pasting it inline. Give the bytes as \
                        `content` (text) or `content_base64` (binary), or a public `url` \
                        the server fetches for you (up to 100 MB). Pass `folder` to file it \
                        under a path like 'reports/2024/q3'. Files are kept until someone \
                        deletes them; pass `ttl_secs` only when the content is meant to \
                        disappear on its own, and say so to the user when you do.",
        "inputSchema": { "type": "object", "properties": {
            "name": { "type": "string", "description": "file name the recipient sees, with its extension (report.md, data.csv, chart.png)" },
            "content": { "type": "string", "description": "the file's text content (UTF-8). Use content_base64 for binary" },
            "content_base64": { "type": "string", "description": "the file's bytes, base64-encoded" },
            "url": { "type": "string", "description": "a public https URL to fetch the file from instead of sending its bytes" },
            "folder": { "type": "string", "description": "where to file it inside the drive, as a path like 'reports/2024/q3'. Missing levels are created. Omit for the drive root" },
            "drive": { "type": "string", "description": "name of an existing drive; omit to use a default drive, which is created on first upload" },
            "ttl_secs": { "type": "integer", "description": "seconds before the file deletes itself (60 minimum). Omit — the usual case — and it is kept until deleted" }
        }, "required": ["name"] }
    })
}

fn tool_specs_local() -> Value {
    json!([
        {
            "name": "create_account",
            "title": "Create a Yogfile account",
            "annotations": { "title": "Create a Yogfile account", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false },
            "description": "Create a fresh anonymous Yogfile account and return its 16-digit \
                            number. You rarely need this: the other tools create an account by \
                            themselves on first use. Call it only when the user explicitly asks \
                            to start over with a new account. The number is saved locally and is \
                            the ONLY credential: if it is lost the account cannot be recovered, \
                            so show it to the user when it is created.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "create_drive",
            "title": "Create a drive",
            "annotations": { "title": "Create a drive", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false },
            "description": "Create a drive and return its short public name (like x7k2p9). A drive \
                            is a flat folder: files live in one, and its URL shows every file it \
                            holds. Use it to group several files under a single URL for someone. \
                            For a single file you do not need this, since upload_file will place \
                            it in a default drive on its own.",
            "inputSchema": { "type": "object", "properties": {
                "private": { "type": "boolean", "description": "require a passphrase to see the file list; a passphrase is generated if you do not supply one" },
                "passphrase": { "type": "string" },
                "default_ttl_secs": { "type": "integer", "description": "seconds before files in this drive delete themselves (60 minimum). Omit, or 0, to keep them until deleted" }
            } }
        },
        {
            "name": "upload_file",
            "title": "Upload a file",
            "annotations": { "title": "Upload a file", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false },
            "description": "Upload a local file and return a stable share URL to hand to the \
                            user. This is the main tool: use it whenever you have produced a \
                            file the user should be able to download, instead of describing a \
                            path they cannot reach. It does the content hash, the signed grant, \
                            the direct upload to the nearest node and the confirmation in one \
                            call. Pass `folder` to file it under a path like 'reports/2024/q3', \
                            which is how you keep a run's output organised instead of dumping \
                            everything at the root. Files are kept until someone deletes them; pass \
                            `ttl_secs` only when the content is meant to disappear on its own, \
                            and say so to the user when you do.",
            "inputSchema": { "type": "object", "properties": {
                "path": { "type": "string", "description": "local file path to read from" },
                "folder": { "type": "string", "description": "where to file it inside the drive, as a path like 'reports/2024/q3'. Missing levels are created. Omit for the drive root" },
                "drive": { "type": "string", "description": "name of an existing drive; omit to use a default drive, which is created on first upload" },
                "name": { "type": "string", "description": "the name the recipient sees; omit to use the file's own name on disk" },
                "ttl_secs": { "type": "integer", "description": "seconds before the file deletes itself (60 minimum). Omit — the usual case — and it is kept until deleted" }
            }, "required": ["path"] }
        },
        {
            "name": "create_folder",
            "title": "Create a folder",
            "annotations": { "title": "Create a folder", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false },
            "description": "Create a folder inside a drive and return its id. Give the full path \
                            from the drive root, like 'reports/2024/q3'; every missing level is \
                            created in one call, and an existing path is returned as is rather \
                            than duplicated. Nesting is unlimited. You rarely need this on its \
                            own, since upload_file creates the path it is given.",
            "inputSchema": { "type": "object", "properties": {
                "path": { "type": "string", "description": "path from the drive root, e.g. 'reports/2024/q3'" },
                "drive": { "type": "string", "description": "drive name; omit to use your default drive" }
            }, "required": ["path"] }
        },
        {
            "name": "share_link",
            "title": "Mint a direct download link",
            "annotations": { "title": "Mint a direct download link", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false },
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
            "title": "List drives and files",
            "annotations": { "title": "List drives and files", "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false },
            "description": "List drives and what is inside them, one folder at a time. \
                            Call it to find the file_id that share_link and delete_file need, to \
                            check what is about to expire, or to see what another run left \
                            behind in a shared drive. A folder is listed by name; pass `folder` \
                            to walk into one. Long folders are truncated and say so.",
            "inputSchema": { "type": "object", "properties": {
                "drive": { "type": "string", "description": "restrict to one drive; omit to list every drive you own" },
                "folder": { "type": "string", "description": "the folder to look inside, as a path like 'reports/2024'. Omit for the top level of the drive" }
            } }
        },
        {
            "name": "delete_file",
            "title": "Delete a file",
            "annotations": { "title": "Delete a file", "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true, "openWorldHint": false },
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

/// Le nom du drive passé en argument. `box` est l'ancien nom du
/// paramètre : un agent qui a mémorisé un appel, ou un script écrit
/// avant le renommage, continue de l'envoyer. Le lire coûte une ligne
/// et évite un « drive not found » incompréhensible côté modèle.
fn drive_arg(args: &Value) -> Option<&str> {
    args["drive"].as_str().or_else(|| args["box"].as_str())
}

pub async fn call_tool(client: &mut ApiClient, name: &str, args: Value) -> Result<String> {
    match name {
        "create_account" if client.remote => Err(anyhow!(
            "not available on the connector: your Yogfile account is the one you \
             connected with. Disconnect and reconnect the connector to switch accounts"
        )),
        "create_account" => client.create_account().await,
        // `create_box` : le nom d'avant. Un agent dont la liste d'outils est
        // figée dans un fichier de configuration l'appelle encore, et il
        // n'a aucune raison de savoir qu'on a changé un mot.
        "create_drive" | "create_box" => client.create_drive(&args).await,
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

pub struct ApiClient {
    base: String,
    /// La façade WEB, distincte de l'API : c'est elle qui sert la
    /// page d'un fichier, celle qu'un humain reçoit.
    web: String,
    http: reqwest::Client,
    state_path: String,
    number: Option<String>,
    token: Option<String>,
    /// Remote : le token vient du connecteur OAuth, on ne provisionne
    /// jamais un compte tout seul et un 401 remonte tel quel (c'est au
    /// client de rafraîchir son token), et `upload_file` prend un
    /// contenu plutôt qu'un chemin.
    pub remote: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct LocalState {
    account_number: Option<String>,
}

impl ApiClient {
    pub fn new(base: String, web: String, state_path: String) -> Self {
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
            remote: false,
        }
    }

    /// Le client d'UNE requête du connecteur : un token de session API
    /// (celui que le token OAuth transporte), rien de persistant.
    pub fn remote(base: &str, web: &str, token: String, http: reqwest::Client) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            web: web.trim_end_matches('/').to_string(),
            http,
            state_path: String::new(),
            number: None,
            token: Some(token),
            remote: true,
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
        if self.remote {
            return Err(anyhow!(
                "your Yogfile session has expired — the client must refresh its token \
                 (reconnect the connector if it does not)"
            ));
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

    async fn create_drive(&mut self, args: &Value) -> Result<String> {
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
                "/v2/drives",
                Some(Value::Object(body)),
            )
            .await?;
        Ok(format!(
            "drive created: {} (private: {})",
            data["name"].as_str().unwrap_or("?"),
            data["private"]
        ))
    }

    /// Le drive par défaut : le premier du compte, créé au besoin.
    async fn default_drive(&mut self) -> Result<String> {
        let drives = self
            .authed(reqwest::Method::GET, "/v2/drives", None)
            .await?;
        if let Some(first) = drives.as_array().and_then(|a| a.first()) {
            return Ok(first["name"].as_str().unwrap_or_default().to_string());
        }
        let data = self
            .authed(reqwest::Method::POST, "/v2/drives", Some(json!({})))
            .await?;
        Ok(data["name"].as_str().unwrap_or_default().to_string())
    }

    async fn create_folder(&mut self, args: &Value) -> Result<String> {
        let path = args["path"].as_str().context("path is required")?;
        let drive_name = match drive_arg(args) {
            Some(b) => b.to_string(),
            None => self.default_drive().await?,
        };
        let data = self
            .authed(
                reqwest::Method::POST,
                &format!("/v2/drives/{drive_name}/folders"),
                Some(json!({ "path": path })),
            )
            .await?;
        Ok(format!(
            "folder {} ready in drive {drive_name}\nfolder_id: {}",
            data["path"].as_str().unwrap_or(path),
            data["folder_id"].as_str().unwrap_or("?"),
        ))
    }

    async fn upload_file(&mut self, args: &Value) -> Result<String> {
        if self.remote {
            return self.upload_file_remote(args).await;
        }
        let path = args["path"].as_str().context("path is required")?;
        let display_name = args["name"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| {
                std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "file".into())
            });
        self.upload_path(path, display_name, args).await
    }

    /// Remote : les octets arrivent dans l'appel (texte ou base64) ou
    /// par une URL publique. On les pose dans un fichier temporaire
    /// puis c'est le même chemin que le binaire local — hash, grant,
    /// PUT streamé vers la node, confirm.
    async fn upload_file_remote(&mut self, args: &Value) -> Result<String> {
        const MAX_REMOTE_BYTES: u64 = 100 * 1024 * 1024;
        let name = args["name"]
            .as_str()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .context("name is required (with its extension)")?
            .to_string();
        let tmp = tempfile::NamedTempFile::new().context("temp file")?;
        let path = tmp.path().to_path_buf();
        if let Some(text) = args["content"].as_str() {
            tokio::fs::write(&path, text.as_bytes()).await?;
        } else if let Some(b64) = args["content_base64"].as_str() {
            use base64::Engine;
            let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(cleaned.as_bytes())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(cleaned.as_bytes()))
                .context("content_base64 is not valid base64")?;
            if bytes.len() as u64 > MAX_REMOTE_BYTES {
                return Err(anyhow!("content is over the 100 MB connector limit"));
            }
            tokio::fs::write(&path, bytes).await?;
        } else if let Some(url) = args["url"].as_str() {
            if !url.starts_with("https://") && !url.starts_with("http://") {
                return Err(anyhow!("url must be http(s)"));
            }
            let resp = self
                .http
                .get(url)
                .send()
                .await
                .with_context(|| format!("fetching {url}"))?;
            if !resp.status().is_success() {
                return Err(anyhow!("fetching {url}: HTTP {}", resp.status()));
            }
            if resp.content_length().unwrap_or(0) > MAX_REMOTE_BYTES {
                return Err(anyhow!("{url} is over the 100 MB connector limit"));
            }
            use tokio::io::AsyncWriteExt;
            let mut f = tokio::fs::File::create(&path).await?;
            let mut stream = resp.bytes_stream();
            let mut total: u64 = 0;
            use futures_util::StreamExt;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                total += chunk.len() as u64;
                if total > MAX_REMOTE_BYTES {
                    return Err(anyhow!("{url} is over the 100 MB connector limit"));
                }
                f.write_all(&chunk).await?;
            }
            f.flush().await?;
        } else {
            return Err(anyhow!(
                "give the file as content (text), content_base64 (binary) or url"
            ));
        }
        let path_str = path.to_string_lossy().into_owned();
        let out = self.upload_path(&path_str, name, args).await;
        drop(tmp);
        out
    }

    async fn upload_path(
        &mut self,
        path: &str,
        display_name: String,
        args: &Value,
    ) -> Result<String> {
        let meta = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("cannot read {path}"))?;
        if !meta.is_file() {
            return Err(anyhow!("{path} is not a file"));
        }
        let size = meta.len() as i64;
        let drive_name = match drive_arg(args) {
            Some(b) => b.to_string(),
            None => self.default_drive().await?,
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
                &format!("/v2/drives/{drive_name}/uploads"),
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
            "uploaded: {display_name} ({size} bytes) to drive {drive_name}\n\
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
        let drives: Vec<String> = match drive_arg(args) {
            Some(b) => vec![b.to_string()],
            None => {
                let all = self
                    .authed(reqwest::Method::GET, "/v2/drives", None)
                    .await?;
                all.as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|b| b["name"].as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default()
            }
        };
        if drives.is_empty() {
            return Ok("no drives yet. upload_file creates one automatically".into());
        }
        let mut out = String::new();
        for name in drives {
            // Un dossier à la fois : l'API ne rend plus l'arbre entier.
            // Elle ne peut pas — un drive peut contenir des dizaines de
            // milliers de dossiers, et les déverser dans le contexte
            // d'un agent ne l'aiderait pas davantage que de les
            // déverser dans un navigateur.
            let query = match args["folder"]
                .as_str()
                .map(str::trim)
                .filter(|f| !f.is_empty())
            {
                Some(f) => format!("?path={}", encode_path(f)),
                None => String::new(),
            };
            let bx = self
                .authed(
                    reqwest::Method::GET,
                    &format!("/v2/drives/{name}{query}"),
                    None,
                )
                .await?;
            out.push_str(&format!(
                "drive {name}{}\n",
                if bx["private"].as_bool().unwrap_or(false) {
                    " (private)"
                } else {
                    ""
                }
            ));
            // Le chemin courant vient du serveur : « f3a2… » ne dit
            // rien à un modèle, « reports/2024 » lui permet de
            // raisonner.
            let empty = vec![];
            let here: String = bx["breadcrumbs"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .filter_map(|c| c["name"].as_str())
                .collect::<Vec<_>>()
                .join("/");
            if !here.is_empty() {
                out.push_str(&format!("  in {here}/\n"));
            }
            let prefix = if here.is_empty() {
                String::new()
            } else {
                format!("{here}/")
            };
            let folders = bx["folders"].as_array().unwrap_or(&empty);
            for f in folders {
                out.push_str(&format!(
                    "  {prefix}{}/\n",
                    f["name"].as_str().unwrap_or("?")
                ));
            }
            let total_folders = bx["counts"]["folders"].as_i64().unwrap_or(0);
            if total_folders > folders.len() as i64 {
                out.push_str(&format!(
                    "  … {} more folders here — pass `folder` to look inside one\n",
                    total_folders - folders.len() as i64
                ));
            }
            match bx["files"].as_array().filter(|f| !f.is_empty()) {
                Some(files) => {
                    for f in files {
                        let dir = prefix.clone();
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
}

/// Encode un chemin pour une query string, sans tirer une crate pour
/// six caractères. Les noms de dossiers sont déjà validés côté API ;
/// ce qui reste à couvrir, ce sont l'espace et les quelques signes qui
/// changeraient le sens de l'URL.
fn encode_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl ApiClient {
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
            "create_drive",
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
