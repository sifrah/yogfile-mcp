//! yogfile-mcp-remote — le connecteur Yogfile (`mcp.yogfile.com`).
//!
//! Le même serveur MCP que le binaire local, mais hébergé : transport
//! Streamable HTTP (POST JSON-RPC sur `/mcp`) et identité par OAuth 2.0
//! (enregistrement dynamique de client + PKCE), ce qu'un client comme
//! claude.ai, Claude Desktop ou Claude Code attend d'un « connecteur ».
//! Zéro installation côté agent.
//!
//! L'identité reste l'ADN du produit : la page d'autorisation ne
//! demande ni email ni mot de passe, juste le numéro de compte à
//! 16 chiffres — ou le crée en un clic, dans le navigateur de la
//! personne (c'est SON IP qui compte pour l'anti-abus de l'API, pas
//! celle de ce serveur). Le serveur est SANS ÉTAT : les codes, les
//! refresh tokens et les client_id sont des blobs chiffrés
//! (ChaCha20-Poly1305) que seul ce serveur sait ouvrir ; l'access
//! token est le JWT de session de l'API lui-même, transmis tel quel en
//! Bearer. Redémarrer ne déconnecte personne.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use yogfile_mcp::{handle, ApiClient};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
/// Un code d'autorisation vit 5 minutes.
const CODE_TTL: i64 = 300;
/// Marge retirée à `expires_in` pour que le client rafraîchisse AVANT
/// que l'API ne refuse le JWT.
const ACCESS_MARGIN: i64 = 60;
/// Un token validé auprès de l'API reste réputé bon ce temps-là sans
/// nouveau round-trip.
const TOKEN_CACHE: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct App {
    /// L'API vue d'ici (souvent en loopback sur la même VM).
    api: String,
    /// L'API vue du NAVIGATEUR de la personne : la page d'autorisation
    /// crée le compte depuis chez elle, pas depuis ce serveur.
    api_public: String,
    web: String,
    public: String,
    http: reqwest::Client,
    cipher: Arc<ChaCha20Poly1305>,
    /// jti des codes déjà échangés (anti-rejeu) → expiration du code.
    used_codes: Arc<Mutex<HashMap<String, i64>>>,
    /// Tokens API validés récemment → instant de validation.
    token_cache: Arc<Mutex<HashMap<String, Instant>>>,
    /// Échecs d'autorisation par IP (numéros faux) : la seule surface
    /// d'énumération de ce serveur.
    auth_fails: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=info".into()),
        )
        .init();
    let api = std::env::var("YOGFILE_API").unwrap_or_else(|_| "https://api.yogfile.com".into());
    let api_public = std::env::var("YOGFILE_API_PUBLIC").unwrap_or_else(|_| {
        if api.starts_with("https://") {
            api.clone()
        } else {
            "https://api.yogfile.com".into()
        }
    });
    let web = std::env::var("YOGFILE_WEB").unwrap_or_else(|_| "https://yogfile.com".into());
    let public = std::env::var("YOGFILE_MCP_PUBLIC_URL")
        .unwrap_or_else(|_| "https://mcp.yogfile.com".into());
    let bind = std::env::var("YOGFILE_MCP_BIND").unwrap_or_else(|_| "127.0.0.1:8082".into());
    let secret = std::env::var("YOGFILE_MCP_SECRET")
        .context("YOGFILE_MCP_SECRET is required (32+ random bytes, hex)")?;
    if secret.len() < 32 {
        return Err(anyhow!("YOGFILE_MCP_SECRET is too short"));
    }
    let key = sha2::Sha256::digest(secret.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| anyhow!("{e}"))?;

    let app = App {
        api: api.trim_end_matches('/').to_string(),
        api_public: api_public.trim_end_matches('/').to_string(),
        web: web.trim_end_matches('/').to_string(),
        public: public.trim_end_matches('/').to_string(),
        http: reqwest::Client::builder()
            .user_agent(format!("yogfile-mcp-remote/{}", env!("CARGO_PKG_VERSION")))
            .build()?,
        cipher: Arc::new(cipher),
        used_codes: Default::default(),
        token_cache: Default::default(),
        auth_fails: Default::default(),
    };

    let router = Router::new()
        .route("/", get(root))
        .route("/healthz", get(|| async { "ok" }))
        .route("/.well-known/oauth-authorization-server", get(as_metadata))
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            get(as_metadata),
        )
        .route("/.well-known/oauth-protected-resource", get(rs_metadata))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(rs_metadata),
        )
        .route("/register", post(register))
        .route("/authorize", get(authorize_page).post(authorize_submit))
        .route("/token", post(token))
        .route(
            "/mcp",
            post(mcp_post)
                .get(|| async { (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]) })
                .delete(|| async { StatusCode::OK }),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!("yogfile-mcp-remote on http://{bind} (public {public})");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ───────────────────────── blobs chiffrés ─────────────────────────

impl App {
    #[cfg(test)]
    fn for_tests() -> Self {
        Self {
            api: "https://api.example".into(),
            api_public: "https://api.example".into(),
            web: "https://www.example".into(),
            public: "https://mcp.example".into(),
            http: reqwest::Client::new(),
            cipher: Arc::new(ChaCha20Poly1305::new_from_slice(&[0u8; 32]).unwrap()),
            used_codes: Default::default(),
            token_cache: Default::default(),
            auth_fails: Default::default(),
        }
    }

    /// `kind` entre dans les données authentifiées : un blob « code »
    /// ne s'ouvre pas comme un « refresh », même forgé par nous.
    fn seal<T: Serialize>(&self, kind: &str, payload: &T) -> Result<String> {
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let plain = serde_json::to_vec(payload)?;
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &plain,
                    aad: kind.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("seal"))?;
        let mut out = nonce.to_vec();
        out.extend(ct);
        Ok(B64.encode(out))
    }

    fn open<T: for<'a> Deserialize<'a>>(&self, kind: &str, blob: &str) -> Result<T> {
        let raw = B64.decode(blob.trim()).map_err(|_| anyhow!("bad blob"))?;
        if raw.len() < 12 + 16 {
            return Err(anyhow!("bad blob"));
        }
        let (nonce, ct) = raw.split_at(12);
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                chacha20poly1305::aead::Payload {
                    msg: ct,
                    aad: kind.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("bad blob"))?;
        Ok(serde_json::from_slice(&plain)?)
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

fn sha256_b64url(s: &str) -> String {
    B64.encode(sha2::Sha256::digest(s.as_bytes()))
}

fn client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    // Derrière Caddy : la première IP de X-Forwarded-For est le client.
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer)
}

// ───────────────────────── métadonnées ─────────────────────────

async fn root(State(app): State<App>) -> Redirect {
    Redirect::temporary(&app.web)
}

async fn as_metadata(State(app): State<App>) -> Json<Value> {
    Json(json!({
        "issuer": app.public,
        "authorization_endpoint": format!("{}/authorize", app.public),
        "token_endpoint": format!("{}/token", app.public),
        "registration_endpoint": format!("{}/register", app.public),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["yogfile"],
        "service_documentation": app.web,
    }))
}

async fn rs_metadata(State(app): State<App>) -> Json<Value> {
    Json(json!({
        "resource": format!("{}/mcp", app.public),
        "authorization_servers": [app.public],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["yogfile"],
        "resource_name": "Yogfile",
        "resource_documentation": app.web,
    }))
}

// ───────────────────────── enregistrement dynamique ─────────────────────────

#[derive(Serialize, Deserialize)]
struct ClientBlob {
    r: Vec<String>,
    n: Option<String>,
    t: i64,
}

fn redirect_ok(u: &str) -> bool {
    if u.starts_with("https://") {
        return true;
    }
    // Les clients de bureau écoutent en local le temps du flux.
    u.starts_with("http://localhost") || u.starts_with("http://127.0.0.1")
}

async fn register(State(app): State<App>, Json(body): Json<Value>) -> Response {
    let uris: Vec<String> = body["redirect_uris"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|u| u.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if uris.is_empty() || !uris.iter().all(|u| redirect_ok(u)) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be https (or http://localhost)"
            })),
        )
            .into_response();
    }
    let name = body["client_name"].as_str().map(str::to_string);
    let blob = ClientBlob {
        r: uris.clone(),
        n: name.clone(),
        t: now(),
    };
    let client_id = match app.seal("client", &blob) {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": blob.t,
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "yogfile",
        })),
    )
        .into_response()
}

// ───────────────────────── autorisation ─────────────────────────

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
    #[allow(dead_code)]
    resource: Option<String>,
}

#[derive(Deserialize)]
struct AuthorizeForm {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: String,
    #[serde(default)]
    account_number: String,
    mfa_context: Option<String>,
    mfa_code: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CodeBlob {
    /// Secret révocable de l'appareil OAuth, jamais le numéro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    /// Compatibilité avec les codes émis avant le MFA. Jamais écrit
    /// dans un nouveau blob et migré vers un appareil à l'échange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    /// sha256(client_id) : lie le code au client enregistré.
    c: String,
    r: String,
    /// code_challenge (S256).
    ch: String,
    exp: i64,
    jti: String,
}

#[derive(Serialize, Deserialize)]
struct RefreshBlob {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    /// Refresh historique chiffré contenant le numéro. Sa première
    /// utilisation réussie émet un nouveau refresh basé sur appareil.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    t: i64,
    jti: String,
}

#[derive(Serialize, Deserialize)]
struct MfaBlob {
    challenge: String,
    c: String,
    r: String,
    ch: String,
    exp: i64,
}

enum StartedSession {
    Authorized(String),
    MfaRequired { challenge: String, exp: i64 },
}

enum OAuthCredential {
    Device(String),
    LegacyNumber(String),
}

fn oauth_credential(device: Option<String>, number: Option<String>) -> Option<OAuthCredential> {
    device
        .map(OAuthCredential::Device)
        .or_else(|| number.map(OAuthCredential::LegacyNumber))
}

/// Valide client_id + redirect_uri + PKCE, ou explique pourquoi non.
fn check_authorize(app: &App, q: &AuthorizeQuery) -> Result<(String, String, String), String> {
    if q.response_type.as_deref() != Some("code") {
        return Err("response_type must be code".into());
    }
    let client_id = q.client_id.clone().ok_or("client_id is required")?;
    let client: ClientBlob = app
        .open("client", &client_id)
        .map_err(|_| "unknown client_id — register first (POST /register)".to_string())?;
    let redirect = q.redirect_uri.clone().ok_or("redirect_uri is required")?;
    if !client.r.iter().any(|r| r == &redirect) {
        return Err("redirect_uri does not match the registered client".into());
    }
    if q.code_challenge_method.as_deref().unwrap_or("S256") != "S256" {
        return Err("only S256 PKCE is supported".into());
    }
    let challenge = q
        .code_challenge
        .clone()
        .filter(|c| c.len() >= 43)
        .ok_or("code_challenge (S256) is required")?;
    Ok((client_id, redirect, challenge))
}

async fn authorize_page(State(app): State<App>, Query(q): Query<AuthorizeQuery>) -> Response {
    match check_authorize(&app, &q) {
        Ok((client_id, redirect, challenge)) => {
            let client: ClientBlob = app.open("client", &client_id).unwrap();
            Html(render_authorize(
                &app,
                &client_id,
                &redirect,
                q.state.as_deref().unwrap_or(""),
                &challenge,
                client.n.as_deref().unwrap_or("your MCP client"),
                None,
                None,
            ))
            .into_response()
        }
        Err(msg) => (StatusCode::BAD_REQUEST, Html(render_error(&msg))).into_response(),
    }
}

async fn authorize_submit(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<AuthorizeForm>,
) -> Response {
    let ip = client_ip(&headers, peer.ip());
    let q = AuthorizeQuery {
        response_type: Some("code".into()),
        client_id: Some(f.client_id.clone()),
        redirect_uri: Some(f.redirect_uri.clone()),
        state: f.state.clone(),
        code_challenge: Some(f.code_challenge.clone()),
        code_challenge_method: Some("S256".into()),
        scope: None,
        resource: None,
    };
    let (client_id, redirect, challenge) = match check_authorize(&app, &q) {
        Ok(v) => v,
        Err(msg) => return (StatusCode::BAD_REQUEST, Html(render_error(&msg))).into_response(),
    };
    let client: ClientBlob = app.open("client", &client_id).unwrap();
    let client_name = client.n.clone().unwrap_or_else(|| "your MCP client".into());
    // Anti-énumération : dix numéros faux par IP et par 10 minutes.
    if too_many_fails(&app, ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(render_authorize(
                &app,
                &client_id,
                &redirect,
                f.state.as_deref().unwrap_or(""),
                &challenge,
                &client_name,
                Some("Too many attempts from your address. Try again in ten minutes."),
                f.mfa_context.as_deref(),
            )),
        )
            .into_response();
    }
    let device_token = if let Some(context) = f.mfa_context.as_deref() {
        let pending: MfaBlob = match app.open::<MfaBlob>("mfa-login", context) {
            Ok(value)
                if value.exp >= now()
                    && value.c == sha256_b64url(&client_id)
                    && value.r == redirect
                    && value.ch == challenge =>
            {
                value
            }
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Html(render_authorize(
                        &app,
                        &client_id,
                        &redirect,
                        f.state.as_deref().unwrap_or(""),
                        &challenge,
                        &client_name,
                        Some("This verification request expired. Start again."),
                        None,
                    )),
                )
                    .into_response()
            }
        };
        let Some(code) = f
            .mfa_code
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            return (
                StatusCode::UNAUTHORIZED,
                Html(render_authorize(
                    &app,
                    &client_id,
                    &redirect,
                    f.state.as_deref().unwrap_or(""),
                    &challenge,
                    &client_name,
                    Some("Enter an authenticator or recovery code."),
                    Some(context),
                )),
            )
                .into_response();
        };
        match api_complete_mfa(&app, &pending.challenge, code, &client_name).await {
            Ok(device) => device,
            Err(_) => {
                record_fail(&app, ip);
                return (
                    StatusCode::UNAUTHORIZED,
                    Html(render_authorize(
                        &app,
                        &client_id,
                        &redirect,
                        f.state.as_deref().unwrap_or(""),
                        &challenge,
                        &client_name,
                        Some("That code is invalid or has already been used."),
                        Some(context),
                    )),
                )
                    .into_response();
            }
        }
    } else {
        let number: String = f
            .account_number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let started = if number.len() == 16 {
            api_start_session(&app, &number, &client_name).await
        } else {
            Err(anyhow!("invalid account number"))
        };
        match started {
            Ok(StartedSession::Authorized(device)) => device,
            Ok(StartedSession::MfaRequired {
                challenge: mfa_challenge,
                exp,
            }) => {
                let context = match app.seal(
                    "mfa-login",
                    &MfaBlob {
                        challenge: mfa_challenge,
                        c: sha256_b64url(&client_id),
                        r: redirect.clone(),
                        ch: challenge.clone(),
                        exp,
                    },
                ) {
                    Ok(value) => value,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                return Html(render_authorize(
                    &app,
                    &client_id,
                    &redirect,
                    f.state.as_deref().unwrap_or(""),
                    &challenge,
                    &client_name,
                    None,
                    Some(&context),
                ))
                .into_response();
            }
            Err(_) => {
                record_fail(&app, ip);
                return (
                    StatusCode::UNAUTHORIZED,
                    Html(render_authorize(
                        &app,
                        &client_id,
                        &redirect,
                        f.state.as_deref().unwrap_or(""),
                        &challenge,
                        &client_name,
                        Some("That account number does not exist. Check the 16 digits, or create a new account."),
                        None,
                    )),
                )
                    .into_response();
            }
        }
    };

    let code = match app.seal(
        "code",
        &CodeBlob {
            d: Some(device_token),
            n: None,
            c: sha256_b64url(&client_id),
            r: redirect.clone(),
            ch: challenge,
            exp: now() + CODE_TTL,
            jti: random_id(),
        },
    ) {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let sep = if redirect.contains('?') { '&' } else { '?' };
    let mut url = format!("{redirect}{sep}code={}", urlencode(&code));
    if let Some(s) = f.state.as_deref().filter(|s| !s.is_empty()) {
        url.push_str(&format!("&state={}", urlencode(s)));
    }
    Redirect::to(&url).into_response()
}

fn too_many_fails(app: &App, ip: IpAddr) -> bool {
    let mut map = app.auth_fails.lock().unwrap();
    let now = Instant::now();
    map.retain(|_, v| {
        v.iter()
            .any(|t| now.duration_since(*t) < Duration::from_secs(600))
    });
    match map.get_mut(&ip) {
        Some(v) => {
            v.retain(|t| now.duration_since(*t) < Duration::from_secs(600));
            v.len() >= 10
        }
        None => false,
    }
}

fn record_fail(app: &App, ip: IpAddr) {
    app.auth_fails
        .lock()
        .unwrap()
        .entry(ip)
        .or_default()
        .push(Instant::now());
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Autorise le connecteur comme appareil. Le JWT court est volontairement
/// jeté ici : l'échange OAuth le renouvellera depuis le secret d'appareil.
async fn api_start_session(app: &App, number: &str, client_name: &str) -> Result<StartedSession> {
    let resp = app
        .http
        .post(format!("{}/v2/sessions", app.api))
        .json(&json!({
            "account_number": number,
            "device_name": format!("MCP · {client_name}"),
        }))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if body["error"]["code"] == "mfa_required" {
        return Ok(StartedSession::MfaRequired {
            challenge: body["error"]["details"]["challenge_id"]
                .as_str()
                .context("incomplete MFA challenge")?
                .to_string(),
            exp: body["error"]["details"]["expires_at"]
                .as_i64()
                .context("missing MFA challenge expiry")?,
        });
    }
    if !status.is_success() {
        return Err(anyhow!(
            "{}",
            body["error"]["message"]
                .as_str()
                .unwrap_or("session refused")
        ));
    }
    let device = body["data"]["device_token"]
        .as_str()
        .context("no device token")?
        .to_string();
    Ok(StartedSession::Authorized(device))
}

async fn api_complete_mfa(
    app: &App,
    challenge: &str,
    code: &str,
    client_name: &str,
) -> Result<String> {
    let normalized: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let method = if normalized.len() == 6 && normalized.bytes().all(|b| b.is_ascii_digit()) {
        "totp"
    } else {
        "recovery_code"
    };
    let resp = app
        .http
        .post(format!("{}/v2/sessions/mfa", app.api))
        .json(&json!({
            "challenge_id": challenge,
            "method": method,
            "code": code,
            "device_name": format!("MCP · {client_name}"),
        }))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!(
            "{}",
            body["error"]["message"]
                .as_str()
                .unwrap_or("MFA verification failed")
        ));
    }
    Ok(body["data"]["device_token"]
        .as_str()
        .context("no device token")?
        .to_string())
}

/// Renouvelle le JWT court sans remettre le numéro dans le refresh
/// token OAuth.
async fn api_device_session(app: &App, device_token: &str) -> Result<(String, i64, String)> {
    let resp = app
        .http
        .post(format!("{}/v2/sessions/refresh", app.api))
        .json(&json!({ "device_token": device_token }))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!(
            "{}",
            body["error"]["message"]
                .as_str()
                .unwrap_or("device authorization refused")
        ));
    }
    let token = body["data"]["token"]
        .as_str()
        .context("no token")?
        .to_string();
    let exp = body["data"]["expires_at"]
        .as_i64()
        .unwrap_or(now() + 24 * 3600);
    let next_device = body["data"]["device_token"]
        .as_str()
        .unwrap_or(device_token)
        .to_string();
    Ok((token, exp, next_device))
}

// ───────────────────────── token ─────────────────────────

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: Option<String>,
    code_verifier: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
}

fn oauth_error(status: StatusCode, code: &str, desc: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": code, "error_description": desc })),
    )
        .into_response()
}

async fn token(State(app): State<App>, Form(f): Form<TokenForm>) -> Response {
    let credential = match f.grant_type.as_str() {
        "authorization_code" => {
            let (Some(code), Some(verifier)) = (f.code.as_deref(), f.code_verifier.as_deref())
            else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "code and code_verifier are required",
                );
            };
            let blob: CodeBlob = match app.open("code", code) {
                Ok(b) => b,
                Err(_) => {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown code")
                }
            };
            if blob.exp < now() {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
            }
            if sha256_b64url(verifier) != blob.ch {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE mismatch");
            }
            if let Some(r) = f.redirect_uri.as_deref() {
                if r != blob.r {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "redirect_uri mismatch",
                    );
                }
            }
            if let Some(c) = f.client_id.as_deref() {
                if sha256_b64url(c) != blob.c {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_client",
                        "client_id mismatch",
                    );
                }
            }
            {
                let mut used = app.used_codes.lock().unwrap();
                let t = now();
                used.retain(|_, exp| *exp > t);
                if used.insert(blob.jti.clone(), blob.exp).is_some() {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "code already used",
                    );
                }
            }
            let Some(credential) = oauth_credential(blob.d, blob.n) else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "authorization code has no account credential",
                );
            };
            credential
        }
        "refresh_token" => {
            let Some(rt) = f.refresh_token.as_deref() else {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "refresh_token is required",
                );
            };
            match app.open::<RefreshBlob>("refresh", rt) {
                Ok(b) => match oauth_credential(b.d, b.n) {
                    Some(credential) => credential,
                    None => {
                        return oauth_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "refresh token has no account credential",
                        )
                    }
                },
                Err(_) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "unknown refresh token",
                    )
                }
            }
        }
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                "use authorization_code or refresh_token",
            )
        }
    };

    let device_token = match credential {
        OAuthCredential::Device(token) => token,
        OAuthCredential::LegacyNumber(number) => {
            match api_start_session(&app, &number, "MCP connector").await {
                Ok(StartedSession::Authorized(token)) => token,
                Ok(StartedSession::MfaRequired { .. }) => {
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "MFA now protects this account. Reconnect the Yogfile connector",
                    )
                }
                Err(error) => {
                    tracing::warn!("legacy connector migration failed: {error}");
                    return oauth_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "the Yogfile account is not reachable. Reconnect it",
                    );
                }
            }
        }
    };

    let (jwt, exp, next_device_token) = match api_device_session(&app, &device_token).await {
        Ok(v) => v,
        Err(e) => {
            // Le compte a disparu (ou l'API est injoignable) : le client
            // doit refaire le flux complet.
            tracing::warn!("session for connector failed: {e}");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the Yogfile account is not reachable. Reconnect it",
            );
        }
    };
    let refresh = match app.seal(
        "refresh",
        &RefreshBlob {
            d: Some(next_device_token),
            n: None,
            t: now(),
            jti: random_id(),
        },
    ) {
        Ok(r) => r,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "access_token": jwt,
            "token_type": "Bearer",
            "expires_in": (exp - now() - ACCESS_MARGIN).max(60),
            "refresh_token": refresh,
            "scope": "yogfile",
        })),
    )
        .into_response()
}

// ───────────────────────── MCP (Streamable HTTP) ─────────────────────────

fn unauthorized(app: &App, desc: &str) -> Response {
    let hv = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\", error=\"invalid_token\", error_description=\"{desc}\"",
        app.public
    );
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_str(&hv).unwrap(),
        )],
        Json(json!({ "error": "invalid_token", "error_description": desc })),
    )
        .into_response()
}

/// Le Bearer est le JWT de session de l'API : on le valide auprès
/// d'elle (`GET /v2/me`), avec un petit cache pour ne pas payer un
/// round-trip par message.
async fn check_token(app: &App, token: &str) -> bool {
    {
        let mut cache = app.token_cache.lock().unwrap();
        cache.retain(|_, t| t.elapsed() < TOKEN_CACHE);
        if cache.contains_key(token) {
            return true;
        }
    }
    let ok = app
        .http
        .get(format!("{}/v2/me", app.api))
        .bearer_auth(token)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if ok {
        app.token_cache
            .lock()
            .unwrap()
            .insert(token.to_string(), Instant::now());
    }
    ok
}

async fn mcp_post(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let Some(token) = token else {
        return unauthorized(&app, "connect your Yogfile account");
    };
    if !check_token(&app, token).await {
        return unauthorized(&app, "session expired or invalid");
    }
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "jsonrpc": "2.0", "id": null,
                    "error": { "code": -32700, "message": "parse error" } })),
            )
                .into_response()
        }
    };
    let mut client = ApiClient::remote(&app.api, &app.web, token.to_string(), app.http.clone());
    let batch = msg.is_array();
    let msgs: Vec<Value> = if batch {
        msg.as_array().cloned().unwrap_or_default()
    } else {
        vec![msg]
    };
    let mut out = Vec::new();
    for m in &msgs {
        if let Some(r) = handle(&mut client, m).await {
            out.push(r);
        }
    }
    if out.is_empty() {
        // Que des notifications (ou des réponses) : accusé, sans corps.
        return StatusCode::ACCEPTED.into_response();
    }
    let payload = if batch {
        Value::Array(out)
    } else {
        out.into_iter().next().unwrap()
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        payload.to_string(),
    )
        .into_response()
}

// ───────────────────────── pages ─────────────────────────

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const PAGE_CSS: &str = r#"
/* Le système de la marque (assets/brand/BRAND.md) : encre #201e1d,
   fond #f3f2f2, accent #ec3013, radius 0, filets 2 px, Archivo. */
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f2f2;color:#201e1d;font:15px/1.5 Archivo,-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
.card{width:min(460px,92vw);background:#fff;border:2px solid #201e1d;padding:32px}
.brand{margin-bottom:22px}
.brand svg{display:block;height:18px;width:auto}
h1{font-size:20px;font-weight:600;margin:0 0 8px;letter-spacing:-.01em}
p{margin:0 0 14px;color:#5b5755}
label{display:block;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;color:#201e1d;margin:18px 0 6px}
input{width:100%;padding:12px 14px;border:2px solid #201e1d;background:#fff;color:#201e1d;font:inherit;font-size:16px;font-variant-numeric:tabular-nums;letter-spacing:.08em;border-radius:0}
input:focus{outline:2px solid #ec3013;outline-offset:2px}
button{width:100%;margin-top:12px;padding:12px;border:2px solid #201e1d;background:#201e1d;color:#f3f2f2;font:inherit;font-weight:600;letter-spacing:.02em;cursor:pointer;border-radius:0}
button:hover{background:#ec3013;border-color:#ec3013}
button.ghost{background:transparent;color:#201e1d}
button.ghost:hover{background:#201e1d;color:#f3f2f2;border-color:#201e1d}
button:disabled{opacity:.5;cursor:default}
.num{font-size:28px;font-weight:600;letter-spacing:.14em;font-variant-numeric:tabular-nums;text-align:center;padding:16px;border:2px solid #201e1d;background:#f3f2f2;margin:10px 0;user-select:all}
.warn{color:#ec3013;font-size:13px}
.err{border:2px solid #ec3013;color:#ec3013;padding:10px 12px;font-size:13px;margin-bottom:8px}
.or{display:flex;align-items:center;gap:10px;color:#8a8582;font-size:12px;margin:20px 0 2px}
.or:before,.or:after{content:"";flex:1;height:2px;background:#e3e0de}
.hide{display:none}
small{color:#8a8582;font-size:12px}
a{color:#201e1d;text-decoration-color:#ec3013;text-underline-offset:3px}
"#;

const LOGO_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -78.89 648.77 89.18" height="18" aria-label="Yogfile" role="img">
  <g transform="translate(-17.08 -93.59) scale(4.7588)" fill="none"><path d="M5 4.5 12 11.5 19 4.5 M5 12 12 19 19 12" stroke="#201e1d" stroke-width="4"></path></g>
  <g transform="translate(120.17 0)"><path d="M40.40 0L27.40 0L27.40-27.90L1-68.60L16-68.60L34.10-39.60L34.60-39.60L52.50-68.60L66.70-68.60L40.40-27.90L40.40 0ZM121.80 1.20L121.80 1.20Q111.10 1.20 103.30-2.65Q95.50-6.50 91.35-14.40Q87.20-22.30 87.20-34.30L87.20-34.30Q87.20-46.40 91.35-54.25Q95.50-62.10 103.30-65.95Q111.10-69.80 121.80-69.80L121.80-69.80Q132.60-69.80 140.35-65.95Q148.10-62.10 152.25-54.25Q156.40-46.40 156.40-34.30L156.40-34.30Q156.40-22.30 152.25-14.40Q148.10-6.50 140.35-2.65Q132.60 1.20 121.80 1.20ZM121.80-9.80L121.80-9.80Q127-9.80 130.95-11.30Q134.90-12.80 137.60-15.75Q140.30-18.70 141.70-23.05Q143.10-27.40 143.10-33.10L143.10-33.10L143.10-35.30Q143.10-41.10 141.70-45.50Q140.30-49.90 137.60-52.85Q134.90-55.80 130.95-57.30Q127-58.80 121.80-58.80L121.80-58.80Q116.60-58.80 112.65-57.30Q108.70-55.80 106-52.85Q103.30-49.90 101.95-45.50Q100.60-41.10 100.60-35.30L100.60-35.30L100.60-33.10Q100.60-27.40 101.95-23.05Q103.30-18.70 106-15.75Q108.70-12.80 112.65-11.30Q116.60-9.80 121.80-9.80ZM214.70 1.20L214.70 1.20Q198.80 1.20 190-7.35Q181.20-15.90 181.20-34.30L181.20-34.30Q181.20-46.40 185.35-54.25Q189.50-62.10 197.35-65.95Q205.20-69.80 216.20-69.80L216.20-69.80Q222.80-69.80 228.60-68.30Q234.40-66.80 238.85-63.75Q243.30-60.70 245.80-56.10Q248.30-51.50 248.30-45.20L248.30-45.20L234.90-45.20Q234.90-48.50 233.45-51.05Q232-53.60 229.45-55.35Q226.90-57.10 223.60-57.95Q220.30-58.80 216.60-58.80L216.60-58.80Q211.10-58.80 206.95-57.35Q202.80-55.90 200.05-52.95Q197.30-50 195.95-45.60Q194.60-41.20 194.60-35.30L194.60-35.30L194.60-33.20Q194.60-25.10 196.90-19.90Q199.20-14.70 203.85-12.25Q208.50-9.80 215.40-9.80L215.40-9.80Q221.30-9.80 225.75-11.60Q230.20-13.40 232.75-16.85Q235.30-20.30 235.30-25.30L235.30-25.30L235.30-26L213.40-26L213.40-36.80L248.30-36.80L248.30 0L239 0L237.90-7.60Q234.90-4.60 231.50-2.65Q228.10-0.70 224 0.25Q219.90 1.20 214.70 1.20ZM290.90 0L277.90 0L277.90-68.60L327.20-68.60L327.20-57.50L290.90-57.50L290.90-39.10L323.60-39.10L323.60-28L290.90-28L290.90 0ZM366.80 0L353.80 0L353.80-68.60L366.80-68.60L366.80 0ZM444.40 0L397 0L397-68.60L410-68.60L410-11.30L444.40-11.30L444.40 0ZM523.10 0L469 0L469-68.60L522.50-68.60L522.50-57.50L482-57.50L482-40.60L518.10-40.60L518.10-29.50L482-29.50L482-11.10L523.10-11.10L523.10 0Z" fill="#201e1d"></path></g>
</svg>"##;

#[allow(clippy::too_many_arguments)]
fn render_authorize(
    app: &App,
    client_id: &str,
    redirect: &str,
    state: &str,
    challenge: &str,
    client_name: &str,
    error: Option<&str>,
    mfa_context: Option<&str>,
) -> String {
    let err_html = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    let form = if let Some(context) = mfa_context {
        format!(
            r#"<div id="verify">
      <h2>Second factor required</h2>
      <p>Enter a code from your authenticator, or one recovery code. This authorizes the connector as a device you can revoke.</p>
      <input type="hidden" name="mfa_context" value="{}">
      <label for="m">Authenticator or recovery code</label>
      <input id="m" name="mfa_code" type="password" autocomplete="one-time-code" placeholder="Code" maxlength="24" autofocus>
      <button type="submit">Verify and connect</button>
    </div>"#,
            esc(context)
        )
    } else {
        r#"<div id="pick">
      <button type="button" id="create">Create a new account</button>
      <div class="or">or use an existing one</div>
      <label for="n">Account number</label>
      <input id="n" name="account_number" type="password" inputmode="numeric" autocomplete="off" placeholder="16 digits" maxlength="16">
      <button type="submit" class="ghost" id="go">Connect</button>
    </div>
    <div id="made" class="hide">
      <label>Your new account</label>
      <div class="num" id="num"></div>
      <p class="warn">Save the number now. It is never shown in full on screen, and there is no email recovery. MFA stays off until you add it in Yogfile settings.</p>
      <button type="button" id="copy">Copy number</button>
      <button type="submit" class="ghost">I saved it, connect</button>
    </div>"#
            .to_string()
    };
    let tpl = r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Yogfile</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;600&display=swap" rel="stylesheet"><style>__CSS__</style></head><body>
<div class="card">
  <div class="brand">__LOGO__</div>
  <h1>Connect Yogfile to __CLIENT__</h1>
  <p>Your agent gets a drive: it can write files, read them back later, and hand out share links. No email or password. A Yogfile account starts with a private 16-digit number and can be protected by MFA.</p>
  __ERR__
  <form method="post" action="/authorize" id="f">
    <input type="hidden" name="client_id" value="__CID__">
    <input type="hidden" name="redirect_uri" value="__REDIR__">
    <input type="hidden" name="state" value="__STATE__">
    <input type="hidden" name="code_challenge" value="__CH__">
    __FORM__
  </form>
  <p style="margin-top:16px"><small>By connecting you accept the <a href="__WEB__/legal/terms">terms</a>. Files stay until you delete them, unless you ask for a lifetime.</small></p>
</div>
<script>
const API="__API__";
const f=document.getElementById('f'),n=document.getElementById('n');
const create=document.getElementById('create');
if(create)create.onclick=async(e)=>{
  const b=e.target;b.disabled=true;b.textContent='Creating…';
  try{
    const r=await fetch(API+'/v2/accounts',{method:'POST'});
    const j=await r.json();
    if(!r.ok||!j.data){throw new Error((j.error&&j.error.message)||'could not create an account');}
    n.value=j.data.account_number;
    document.getElementById('num').textContent='•••• •••• •••• '+j.data.account_number.slice(-4);
    document.getElementById('pick').classList.add('hide');
    document.getElementById('made').classList.remove('hide');
  }catch(err){alert(err.message);b.disabled=false;b.textContent='Create a new account';}
};
const copy=document.getElementById('copy');
if(copy)copy.onclick=(e)=>{navigator.clipboard.writeText(n.value).then(()=>{e.target.textContent='Copied';});};
f.onsubmit=(e)=>{if(n){n.value=n.value.replace(/\D/g,'');if(n.value.length!==16){e.preventDefault();alert('An account number has 16 digits.');}}};
</script></body></html>"#;
    tpl.replace("__CSS__", PAGE_CSS)
        .replace("__LOGO__", LOGO_SVG)
        .replace("__CLIENT__", &esc(client_name))
        .replace("__ERR__", &err_html)
        .replace("__FORM__", &form)
        .replace("__CID__", &esc(client_id))
        .replace("__REDIR__", &esc(redirect))
        .replace("__STATE__", &esc(state))
        .replace("__CH__", &esc(challenge))
        .replace("__WEB__", &esc(&app.web))
        .replace("__API__", &esc(&app.api_public))
}

fn render_error(msg: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Yogfile</title><style>{}</style></head><body><div class="card"><div class="brand">{}</div><h1>Cannot start the connection</h1><p>{}</p><p><small>The MCP client sent an authorization request this server cannot honour. Try removing and re-adding the Yogfile connector.</small></p></div></body></html>"#,
        PAGE_CSS,
        LOGO_SVG,
        esc(msg)
    )
}

#[cfg(test)]
mod mfa_tests {
    use super::*;

    #[test]
    fn oauth_sealed_values_never_contain_an_account_number_field() {
        let code = serde_json::to_value(CodeBlob {
            d: Some("ydt_secret".into()),
            n: None,
            c: "client".into(),
            r: "https://client.example/callback".into(),
            ch: "pkce".into(),
            exp: 1,
            jti: "one".into(),
        })
        .unwrap();
        let refresh = serde_json::to_value(RefreshBlob {
            d: Some("ydt_secret".into()),
            n: None,
            t: 1,
            jti: "two".into(),
        })
        .unwrap();

        assert!(code.get("n").is_none());
        assert!(refresh.get("n").is_none());
        assert_eq!(code["d"], "ydt_secret");
    }

    #[test]
    fn legacy_refreshes_are_readable_for_one_way_migration() {
        let legacy: RefreshBlob = serde_json::from_value(json!({
            "n": "legacy-number",
            "t": 1,
            "jti": "old",
        }))
        .unwrap();

        assert!(matches!(
            oauth_credential(legacy.d, legacy.n),
            Some(OAuthCredential::LegacyNumber(value)) if value == "legacy-number"
        ));
    }

    #[test]
    fn mfa_page_has_only_a_hidden_factor_input() {
        let app = App::for_tests();
        let html = render_authorize(
            &app,
            "client",
            "https://client.example/callback",
            "state",
            "pkce",
            "Test client",
            None,
            Some("sealed-context"),
        );

        assert!(html.contains("name=\"mfa_code\" type=\"password\""));
        assert!(!html.contains("name=\"account_number\""));
    }
}
