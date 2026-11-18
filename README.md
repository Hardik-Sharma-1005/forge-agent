# Forge Agent — Permanent MCP Workspace Server

A secure, high-performance, permanent Model Context Protocol (MCP) workspace server for **Forge Agent**, connecting Visual Studio Code and TrueForge to local workspace tools.

---

## Architecture Overview

```text
             VS CODE (Forge Agent Extension)
                           │
                           ▼
                    TRUEFORGE AGENT
                           │
                           ▼ (Streamable HTTP / Bearer Auth)
              PERMANENT MCP WORKSPACE SERVER
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
    Security & Boundary Layer       MCP Tool Handlers
    - Loopback only (127.0.0.1)     1. get_workspace_context
    - Timing-safe Bearer auth       2. list_files
    - Traversal & ADS prevention    3. read_file
    - Symlink escape protection     4. search_files
    - Deny-by-default exclusions
             │                           │
             └─────────────┬─────────────┘
                           ▼
                  AUTHORIZED WORKSPACE
```

---

## Key Features

- **Official Model Context Protocol (MCP)**: Implemented using `@modelcontextprotocol/sdk` (v1.32.2) and `zod` (v4.6.7) over Streamable HTTP transport.
- **Strict Read-Only Enforcement**: Exposes only workspace inspection tools. No command execution, terminal access, file modification, or deletion.
- **Hardened Loopback Binding**: Binds exclusively to `127.0.0.1`. Protects against DNS rebinding and CSRF by validating `Host` and `Origin` headers.
- **Constant-Time Bearer Authentication**: Uses `crypto.timingSafeEqual` to verify tokens. Missing or invalid tokens immediately yield HTTP 401.
- **Workspace Isolation & Symlink Protection**: Validates canonical realpaths, prevents path traversal (`..`), Alternate Data Streams (`:`), null bytes, and symlinks resolving outside the root.
- **Deny-by-Default Sensitive Filtering**: Excludes `.env*`, `.git`, `node_modules`, private keys (`.pem`, `.key`, `id_rsa`), certificates, and credentials from listings, reads, and searches.
- **Drop-in Compatibility**: Functions as both a standalone CLI daemon and an exportable module directly compatible with the Forge Agent VS Code extension.

---

## Exposed MCP Tools

| Tool | Purpose | Key Inputs | Output Summary |
|---|---|---|---|
| `get_workspace_context` | Workspace discovery | *(none)* | Workspace root, name, top-level visible items, config files, detected source file extensions, structure summary |
| `list_files` | Relative directory listing | `path` (opt), `recursive` (bool), `max_results` (int) | List of relative file paths, `truncated` boolean flag |
| `read_file` | Read regular UTF-8 text file | `path` (string) | Workspace-relative path and full file content (max 1 MiB) |
| `search_files` | Case-insensitive literal text search | `query` (string), `path` (opt), `max_results` (int) | Matching file paths, 1-indexed line numbers, concise snippets |

---

## Quick Start

### 1. Installation

```powershell
# In PowerShell:
npm install
npm run check
npm test
```

### 2. Run the MCP Server (CLI)

```powershell
# Start server listening on port 8765
node src/server.js --workspace "C:\path\to\your\project" --port 8765 --token "your-secret-token"
```

Command Prompt (CMD) alternative:
```cmd
set FORGE_WORKSPACE_ROOT=C:\path\to\your\project
set FORGE_MCP_PORT=8765
set FORGE_MCP_TOKEN=your-secret-token
node src/server.js
```

### 3. Connect to TrueForge

Ensure TrueForge allows loopback connections:
```powershell
$env:OUTBOUND_URL_ALLOWED_HOSTS = '["127.0.0.1"]'
npx @truefoundry/trueforge
```

In TrueForge Settings → Connectors:
- **Connector Name**: `forge-agent-workspace`
- **URL**: `http://127.0.0.1:8765/mcp`
- **Auth Type**: Header (`Authorization: Bearer <your-secret-token>`)

---

## Test Suite

The test suite runs with Node's built-in `node:test` runner (62 tests, 0 dependencies):

```powershell
# Run all tests
npm test

# Run individual suites
node --test tests/security.test.js
node --test tests/auth.test.js
node --test tests/tools.test.js
node --test tests/stability.test.js
```

See [docs/MCP_SERVER.md](docs/MCP_SERVER.md) for full engineering documentation, integration guide, and security policy.
