# yogfile-mcp

[Yogfile](https://yogfile.com) for AI agents: an MCP server that lets
any agent upload files and hand back share links that expire. One
binary, stdio, no account setup — the server provisions its own
16-digit account on first use and keeps it in
`~/.config/yogfile/mcp.json`.

## Install

```sh
curl -sSfL https://yogfile.com/install.sh | sh
```

Prebuilt for Linux and macOS (x86_64, arm64), checksums verified,
provenance attested (`gh attestation verify <tarball> --repo sifrah/yogfile-mcp`).
Or from source: `cargo install --git https://github.com/sifrah/yogfile-mcp`.

## Hook it into your agent

```sh
# Claude Code
claude mcp add yogfile -- yogfile-mcp
```

```json
// Claude Desktop, Cursor, and any MCP client
{ "mcpServers": { "yogfile": { "command": "yogfile-mcp" } } }
```

## Tools

| Tool | What it does |
|---|---|
| `upload_file` | BLAKE3 the bytes, PUT them **directly** on the storage node the geo-DNS picks, confirm, and return a share link that expires |
| `share_link` | mint a fresh short-lived download link for a file |
| `list_files` | list what's in a box (folders included) |
| `create_folder` | create a folder path in a box |
| `delete_file` | delete a file now |
| `create_box` | create a shareable box (collection) |
| `create_account` | force a new account (one is created automatically otherwise) |

Everything expires: 7 days by default, 30 days maximum on the free
plan. Files never transit through the Yogfile API — the agent talks
to the storage nodes directly with signed headers.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `YOGFILE_API` | `https://api.yogfile.com` | the Yogfile API to talk to |
| `YOGFILE_WEB` | `https://yogfile.com` | the site whose `/f/<id>` pages are handed back |
| `YOGFILE_MCP_STATE` | `~/.config/yogfile/mcp.json` | where the account number lives |

## License

AGPL-3.0. Yogfile runs on [Nauka](https://getnauka.com).
