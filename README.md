# yogfile-mcp

[Yogfile](https://yogfile.com) is a drive for AI agents: storage an
agent writes to, reads back on the next run, and shares by URL. This
is its MCP server. Nothing here is tied to one model or one client:
the connector is plain MCP, and every operation behind it is a public
HTTP API for whatever does not speak MCP.

One binary, stdio, no account setup: the server provisions its own
16-digit account on first use and keeps it in
`~/.config/yogfile/mcp.json`.

## The connector (nothing to install)

Yogfile is a hosted MCP server at `https://mcp.yogfile.com/mcp`:
Streamable HTTP with OAuth 2.0 (dynamic client registration + PKCE),
which is what claude.ai, Claude Desktop and Claude Code call a
*connector*. Any other MCP client takes the same URL. On first use a
page asks for your 16-digit Yogfile account number, or creates one in
a click. The complete number stays masked on screen and can be copied.
If the account has MFA enabled, the page also asks for an authenticator
or recovery code.

```sh
# Claude Code
claude mcp add --transport http yogfile https://mcp.yogfile.com/mcp
```

claude.ai / Claude Desktop: *Settings → Connectors → Add custom
connector*, URL `https://mcp.yogfile.com/mcp`. Cursor and others: an
entry with `"url": "https://mcp.yogfile.com/mcp"`.

On the connector, `upload_file` takes the bytes in the call (`content`
or `content_base64`) or a public `url`, up to 100 MB — a hosted server
cannot read the agent's disk.

## The local binary (large files from disk)

```sh
curl -sSfL https://yogfile.com/install.sh | sh
claude mcp add yogfile -- yogfile-mcp
```

```json
// Claude Desktop, Cursor, and any MCP client
{ "mcpServers": { "yogfile": { "command": "yogfile-mcp" } } }
```

Prebuilt for Linux and macOS (x86_64, arm64), checksums verified,
provenance attested (`gh attestation verify <tarball> --repo sifrah/yogfile-mcp`).
Or from source: `cargo install --git https://github.com/sifrah/yogfile-mcp`.
Its `upload_file` takes a local `path` and streams the bytes straight
from disk to the storage node.

MFA is optional and off by default. To authorize this binary for an
account where MFA is on, run `yogfile-mcp auth` once in a terminal,
then restart the MCP client. Both the account number and factor are
entered with hidden input. The resulting revocable device secret is
kept in the local state file and renews daily sessions automatically.

## Tools

| Tool | What it does |
|---|---|
| `upload_file` | BLAKE3 the bytes, PUT them **directly** on the storage node the geo-DNS picks, confirm, and return a stable share link (local: from a `path`; connector: from `content`/`content_base64`/`url`) |
| `share_link` | mint a fresh short-lived download link for a file |
| `list_files` | list what's in a drive (folders included) |
| `create_folder` | create a folder path in a drive |
| `delete_file` | move a file to Yogfile Trash; its page closes immediately, issued capability URLs remain valid only until their short expiry, and the owner can restore it for 30 days |
| `create_drive` | create a drive: a named place that outlives the session, holding folders and files |
| `create_account` | local binary only: force a new account (one is created automatically otherwise) |

Files stay until someone deletes them. Deleted files spend 30 days in
Yogfile Trash unless the owner purges them sooner. A lifetime is a
policy you ask for, not a default: `default_ttl_secs` on a drive,
`ttl_secs` on a single upload, and a sweeper honours the date. Files
never transit through the Yogfile API — the agent talks to the storage
nodes directly with signed headers.

Moving a file to Trash disables its stable page and prevents any new
download link from being minted. A signed capability URL already handed
to someone is autonomous and remains usable only until the expiry embedded
in that URL (ten minutes by default).

## Running the connector yourself

`cargo build --release --features remote --bin yogfile-mcp-remote`.
It is stateless: codes, refresh tokens and client ids are encrypted
blobs. A refresh token contains a revocable device authorization,
never the account number; the access token is the Yogfile API session
JWT. Environment:
`YOGFILE_MCP_SECRET` (required, 32+ random bytes), `YOGFILE_MCP_BIND`
(`127.0.0.1:8082`), `YOGFILE_MCP_PUBLIC_URL` (`https://mcp.yogfile.com`),
`YOGFILE_API` (as seen from the server), `YOGFILE_API_PUBLIC` (as seen from
the user's browser, default `https://api.yogfile.com`), `YOGFILE_WEB`. Put it behind a TLS reverse proxy that
sets `X-Forwarded-For`.

## Configuration (local binary)

| Variable | Default | Purpose |
|---|---|---|
| `YOGFILE_API` | `https://api.yogfile.com` | the Yogfile API to talk to |
| `YOGFILE_WEB` | `https://yogfile.com` | the site whose `/f/<id>` pages are handed back |
| `YOGFILE_MCP_STATE` | `~/.config/yogfile/mcp.json` | account identity and revocable device secret (mode 0600 on Unix) |

## License

AGPL-3.0. Yogfile runs on [Nauka](https://getnauka.com).
