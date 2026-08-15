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
    account_number: String,
}

#[derive(Serialize, Deserialize)]
struct CodeBlob {
    /// Numéro de compte.
    n: String,
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
    n: String,
    t: i64,
    jti: String,
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
    let number: String = f
        .account_number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();

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
            )),
        )
            .into_response();
    }
    if number.len() != 16 || api_session(&app, &number).await.is_err() {
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
            )),
        )
            .into_response();
    }

    let code = match app.seal(
        "code",
        &CodeBlob {
            n: number,
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

/// Ouvre une session API pour ce numéro : (jwt, exp).
async fn api_session(app: &App, number: &str) -> Result<(String, i64)> {
    let resp = app
        .http
        .post(format!("{}/v2/sessions", app.api))
        .json(&json!({ "account_number": number }))
        .send()
        .await?;
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(anyhow!(
            "{}",
            body["error"]["message"]
                .as_str()
                .unwrap_or("session refused")
        ));
    }
    let token = body["data"]["token"]
        .as_str()
        .context("no token")?
        .to_string();
    let exp = body["data"]["expires_at"]
        .as_i64()
        .unwrap_or(now() + 24 * 3600);
    Ok((token, exp))
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
    let number = match f.grant_type.as_str() {
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
            blob.n
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
                Ok(b) => b.n,
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

    let (jwt, exp) = match api_session(&app, &number).await {
        Ok(v) => v,
        Err(e) => {
            // Le compte a disparu (ou l'API est injoignable) : le client
            // doit refaire le flux complet.
            tracing::warn!("session for connector failed: {e}");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the Yogfile account is not reachable — reconnect",
            );
        }
    };
    let refresh = match app.seal(
        "refresh",
        &RefreshBlob {
            n: number,
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
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0c0a09;color:#e7e5e4;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}
.card{width:min(440px,92vw);background:#1c1917;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:28px}
h1{font-size:19px;margin:0 0 6px;letter-spacing:-.01em}
p{margin:0 0 14px;color:#a8a29e}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:18px;font-weight:600;color:#fafaf9}
.brand span{display:inline-block;width:10px;height:10px;border-radius:3px;background:#f59e0b}
label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#78716c;margin:16px 0 6px}
input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.12);background:#0c0a09;color:#fafaf9;font:inherit;font-variant-numeric:tabular-nums;letter-spacing:.06em}
input:focus{outline:2px solid #f59e0b;outline-offset:1px}
button{width:100%;margin-top:12px;padding:12px;border-radius:10px;border:0;background:#f59e0b;color:#1c1917;font:inherit;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:#e7e5e4;border:1px solid rgba(255,255,255,.14)}
button:disabled{opacity:.5;cursor:default}
.num{font-size:26px;letter-spacing:.14em;font-variant-numeric:tabular-nums;text-align:center;padding:14px;border-radius:10px;background:#0c0a09;border:1px dashed rgba(245,158,11,.5);margin:12px 0;user-select:all}
.warn{color:#fbbf24;font-size:13px}
.err{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35);color:#fca5a5;padding:10px 12px;border-radius:10px;font-size:13px;margin-bottom:8px}
.or{display:flex;align-items:center;gap:10px;color:#57534e;font-size:12px;margin:18px 0 4px}
.or:before,.or:after{content:"";flex:1;height:1px;background:rgba(255,255,255,.08)}
.hide{display:none}
small{color:#78716c;font-size:12px}
a{color:#fbbf24}
"#;

#[allow(clippy::too_many_arguments)]
fn render_authorize(
    app: &App,
    client_id: &str,
    redirect: &str,
    state: &str,
    challenge: &str,
    client_name: &str,
    error: Option<&str>,
) -> String {
    let err_html = error
        .map(|e| format!(r#"<div class="err">{}</div>"#, esc(e)))
        .unwrap_or_default();
    let tpl = r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Yogfile</title><style>__CSS__</style></head><body>
<div class="card">
  <div class="brand"><span></span> Yogfile</div>
  <h1>Connect Yogfile to __CLIENT__</h1>
  <p>Your agent will be able to upload files and hand out share links that expire. No email, no password: a Yogfile account is a 16-digit number.</p>
  __ERR__
  <form method="post" action="/authorize" id="f">
    <input type="hidden" name="client_id" value="__CID__">
    <input type="hidden" name="redirect_uri" value="__REDIR__">
    <input type="hidden" name="state" value="__STATE__">
    <input type="hidden" name="code_challenge" value="__CH__">
    <div id="pick">
      <button type="button" id="create">Create a new account</button>
      <div class="or">or use an existing one</div>
      <label for="n">Account number</label>
      <input id="n" name="account_number" inputmode="numeric" autocomplete="off" placeholder="16 digits" maxlength="19">
      <button type="submit" class="ghost" id="go">Connect</button>
    </div>
    <div id="made" class="hide">
      <label>Your new account number</label>
      <div class="num" id="num"></div>
      <p class="warn">Save it now. It is the account: there is no email, no reset, no recovery. It is also stored by __CLIENT__ for this connection.</p>
      <button type="button" id="copy">Copy number</button>
      <button type="submit" class="ghost">I saved it — connect</button>
    </div>
  </form>
  <p style="margin-top:16px"><small>By connecting you accept the <a href="__WEB__/legal/terms">terms</a>. Files expire after 7 days by default, 30 at most.</small></p>
</div>
<script>
const API="__API__";
const f=document.getElementById('f'),n=document.getElementById('n');
document.getElementById('create').onclick=async(e)=>{
  const b=e.target;b.disabled=true;b.textContent='Creating…';
  try{
    const r=await fetch(API+'/v2/accounts',{method:'POST'});
    const j=await r.json();
    if(!r.ok||!j.data){throw new Error((j.error&&j.error.message)||'could not create an account');}
    n.value=j.data.account_number;
    document.getElementById('num').textContent=j.data.account_number.replace(/(\d{4})(?=\d)/g,'$1 ');
    document.getElementById('pick').classList.add('hide');
    document.getElementById('made').classList.remove('hide');
  }catch(err){alert(err.message);b.disabled=false;b.textContent='Create a new account';}
};
document.getElementById('copy').onclick=(e)=>{navigator.clipboard.writeText(n.value).then(()=>{e.target.textContent='Copied';});};
f.onsubmit=(e)=>{n.value=n.value.replace(/\D/g,'');if(n.value.length!==16){e.preventDefault();alert('An account number has 16 digits.');}};
</script></body></html>"#;
    tpl.replace("__CSS__", PAGE_CSS)
        .replace("__CLIENT__", &esc(client_name))
        .replace("__ERR__", &err_html)
        .replace("__CID__", &esc(client_id))
        .replace("__REDIR__", &esc(redirect))
        .replace("__STATE__", &esc(state))
        .replace("__CH__", &esc(challenge))
        .replace("__WEB__", &esc(&app.web))
        .replace("__API__", &esc(&app.api_public))
}

fn render_error(msg: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Yogfile</title><style>{}</style></head><body><div class="card"><div class="brand"><span></span> Yogfile</div><h1>Cannot start the connection</h1><p>{}</p><p><small>The MCP client sent an authorization request this server cannot honour. Try removing and re-adding the Yogfile connector.</small></p></div></body></html>"#,
        PAGE_CSS,
        esc(msg)
    )
}
