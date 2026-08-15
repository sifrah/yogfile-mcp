# yogfile-mcp

[Yogfile](https://yogfile.com) for AI agents: an MCP server that lets
any agent upload files and hand back share links that expire. One
binary, stdio, no account setup — the server provisions its own
16-digit account on first use and keeps it in
`~/.config/yogfile/mcp.json`.

## The connector (nothing to install)

Yogfile is a hosted MCP server at `https://mcp.yogfile.com/mcp` —
Streamable HTTP with OAuth 2.0 (dynamic client registration + PKCE),
which is what claude.ai, Claude Desktop and Claude Code call a
*connector*. On first use a page asks for your 16-digit Yogfile
account number, or creates one in a click.

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

## Tools

| Tool | What it does |
|---|---|
| `upload_file` | BLAKE3 the bytes, PUT them **directly** on the storage node the geo-DNS picks, confirm, and return a share link that expires (local: from a `path`; connector: from `content`/`content_base64`/`url`) |
| `share_link` | mint a fresh short-lived download link for a file |
| `list_files` | list what's in a box (folders included) |
| `create_folder` | create a folder path in a box |
| `delete_file` | delete a file now |
| `create_box` | create a shareable box (collection) |
| `create_account` | local binary only: force a new account (one is created automatically otherwise) |

Everything expires: 7 days by default, 30 days maximum on the free
plan. Files never transit through the Yogfile API — the agent talks
to the storage nodes directly with signed headers.

## Running the connector yourself

`cargo build --release --features remote --bin yogfile-mcp-remote`.
It is stateless: codes, refresh tokens and client ids are encrypted
blobs, the access token is the Yogfile API session JWT. Environment:
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
| `YOGFILE_MCP_STATE` | `~/.config/yogfile/mcp.json` | where the account number lives |

## License

AGPL-3.0. Yogfile runs on [Nauka](https://getnauka.com).
