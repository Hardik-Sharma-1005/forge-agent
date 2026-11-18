# Forge Agent — Permanent MCP Workspace Server
## Comprehensive Engineering & Operations Guide

The **Permanent MCP Workspace Server** provides secure, local, read-only filesystem inspection capabilities for Forge Agent and TrueForge. Built using the official Model Context Protocol (MCP) SDK and Streamable HTTP transport, it replaces temporary bridge scripts with a hardened, production-grade workspace server.

---

## 1. Overview & Capabilities

The server exposes four standard read-only MCP tools to TrueForge:
1. `get_workspace_context`: Discovers workspace name, root path, visible top-level structure, configuration files, and detected source file extensions.
2. `list_files`: Enumerates workspace-relative files and folders with configurable recursion and result limits.
3. `read_file`: Reads UTF-8 source files up to 1 MiB while refusing binary, oversized, or sensitive files.
4. `search_files`: Searches text files for literal case-insensitive substrings, returning matching paths, 1-indexed line numbers, and truncated snippets.

### Core Guarantees:
- **Strict Read-Only Least Privilege**: Absolutely no write, delete, shell, terminal, or arbitrary command execution capabilities.
- **Loopback-Only Isolation**: Binds strictly to `127.0.0.1` (never `0.0.0.0`). Validates `Host` and `Origin` headers to prevent DNS rebinding and cross-site request attacks.
- **Timing-Safe Authentication**: Authenticates all requests via HTTP `Authorization: Bearer <token>` using constant-time comparison (`crypto.timingSafeEqual`).
- **Deny-by-Default File Security**: Excludes environment files (`.env*`), private keys, credential stores, version control databases (`.git`), dependency folders (`node_modules`), build artifacts (`dist`, `build`), and secret patterns from listings, direct reads, and search results.
- **Path Traversal & Symlink Protection**: Blocks `..`, `\`, drive letters (`C:`), Windows Alternate Data Streams (`:`), null bytes, and symlinks resolving outside the authorized workspace root.

---

## 2. Technical Architecture

```text
                  VS CODE
                     │
                     ▼
             FORGE AGENT EXTENSION
                     │
                     ▼
               TRUEFORGE AGENT
                     │
                     ▼ (Streamable HTTP / JSON-RPC over loopback)
          PERMANENT MCP SERVER (:8765/mcp)
          ┌──────────┴──────────┐
          ▼                     ▼
     HTTP Auth / Host     Security Layer (deny-by-default,
     Validation Guard     realpath boundary, symlink protection)
          │                     │
          └──────────┬──────────┘
                     ▼
              WORKSPACE TOOLS
    [get_context, list, read, search]
                     │
                     ▼
             AUTHORIZED WORKSPACE
```

---

## 3. Prerequisites

- **Node.js**: v20.0.0 or later (v22 / v24 recommended)
- **TrueForge**: Local TrueForge instance running (e.g., `http://localhost:8790`)
- **Network Configuration**: TrueForge requires outbound URL permission for loopback servers:
  ```powershell
  $env:OUTBOUND_URL_ALLOWED_HOSTS = '["127.0.0.1"]'
  ```

---

## 4. Installation & Verification

Clone the repository and install dependencies in the offline workspace:

### Windows PowerShell
```powershell
cd C:\path\to\forge-agent
npm install
npm run check
npm test
```

### Windows Command Prompt (CMD)
```cmd
cd C:\path\to\forge-agent
npm install
npm run check
npm test
```

---

## 5. Configuration & Environment Variables

| Variable | CLI Flag | Default | Description |
|---|---|---|---|
| `FORGE_WORKSPACE_ROOT` | `-w`, `--workspace` | Current working directory | Absolute path to the authorized project workspace |
| `FORGE_MCP_PORT` | `-p`, `--port` | `8765` (`0` for OS dynamic port) | Loopback port to listen on `127.0.0.1` |
| `FORGE_MCP_TOKEN` | `-t`, `--token` | Auto-generated 32-byte hex string | Secret Bearer authentication token |
| N/A | `--token-file` | None | Path to write token with restricted permissions (`0600`) |

---

## 6. Starting the Server

### Option A: Standalone CLI (Recommended for external server daemon)

#### Windows PowerShell
```powershell
# Start with explicit workspace and token
$env:FORGE_WORKSPACE_ROOT = "C:\Users\username\my-project"
$env:FORGE_MCP_PORT = "8765"
$env:FORGE_MCP_TOKEN = "your-cryptographically-random-token-here"
node src/server.js
```

Or pass via command-line arguments:
```powershell
node src/server.js -w "C:\Users\username\my-project" -p 8765 -t "your-secure-token"
```

#### Windows Command Prompt (CMD)
```cmd
set FORGE_WORKSPACE_ROOT=C:\Users\username\my-project
set FORGE_MCP_PORT=8765
set FORGE_MCP_TOKEN=your-cryptographically-random-token-here
node src/server.js
```

### Option B: Programmatic Integration (Directly inside VS Code Extension)
```javascript
const { createPermanentMcpServer, registerPermanentMcpServer } = require('./src/server');

// Initialize server
const server = await createPermanentMcpServer({
  workspaceRoot: () => vscode.workspace.workspaceFolders[0].uri.fsPath,
  port: 0 // Dynamic port
});

console.log(`MCP server active at: ${server.url}`);

// Connect to TrueForge client
await registerPermanentMcpServer({
  client: trueForgeClient,
  url: server.url,
  token: server.token,
  agentName: 'forge-agent'
});
```

---

## 7. Connecting TrueForge to the Permanent Server

1. **Allow Outbound Host in TrueForge**:
   TrueForge blocks loopback URLs by default. Set the environment variable before starting TrueForge:
   ```powershell
   $env:OUTBOUND_URL_ALLOWED_HOSTS = '["127.0.0.1"]'
   npx @truefoundry/trueforge
   ```

2. **Add Remote Connector in TrueForge UI / API**:
   - Connector Name: `forge-agent-workspace`
   - URL: `http://127.0.0.1:8765/mcp`
   - Type: `Remote`
   - Authentication: Header
   - Header Key: `Authorization`
   - Header Value: `Bearer <your-token>`

3. **Attach Tools to Saved Agent (`forge-agent`)**:
   Ensure the following 4 tools are enabled on the agent:
   - `get_workspace_context`
   - `list_files`
   - `read_file`
   - `search_files`

---

## 8. Security Architecture & Policy

### Workspace Isolation & Boundary Defense
1. **Canonical Root Resolution**: The workspace root is resolved via `fs.realpath` at initialization.
2. **Path Sanitization**:
   - Rejects null bytes (`\0`).
   - Rejects POSIX absolute paths (`/path`) and Windows absolute paths (`C:\path`, `\\unc\share`).
   - Rejects path traversal sequences (`..`).
   - Rejects Windows Alternate Data Streams (`filename:stream`).
3. **Symlink Escape Protection**:
   - Candidate paths are resolved, checked against the workspace root, and canonicalized using `fs.realpath`.
   - If a symlink resolves to a target outside the workspace root, access is rejected immediately.
   - Symlinked directories are skipped during directory traversal to prevent infinite recursion and directory escapes.

### Deny-by-Default Sensitive File Exclusions
The following paths are excluded from `get_workspace_context`, `list_files`, `read_file`, and `search_files`:
- **Directories**: `.git`, `node_modules`, `dist`, `build`, `out`, `target`, `coverage`, `.next`, `.nuxt`, `.turbo`, `.cache`, `.parcel-cache`, `.venv`, `venv`, `__pycache__`, `vendor`, `.aws`, `.ssh`, `.gnupg`, `.azure`, `.kube`, `.idea`.
- **Environment Files**: Anything beginning with `.env` (`.env`, `.env.local`, `.env.production`, etc.).
- **Private Keys & Certificates**: `.pem`, `.key`, `.p12`, `.pfx`, `.p7b`, `.p7c`, `.p8`, `.jks`, `.keystore`, `.crt`, `.cer`, `.der`, `.kdbx`.
- **Secret Patterns**: Any path segment matching `/(^|[._-])(secret|secrets|credential|credentials|token|tokens|password|passwords|id_rsa|id_ed25519)([._-]|$)/i`.
- **Known Sensitive Files**: `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `known_hosts`, `authorized_keys`, `.dockercfg`, `htpasswd`.

### Resource & Safety Limits
- **File Read Size Limit**: 1 MiB (`1024 * 1024` bytes).
- **Binary File Detection**: File buffers are scanned for null bytes (`\0`); binary reads are refused.
- **Search Limits**: Maximum 500 files examined, maximum 20 MiB text scanned, maximum 500 characters per matching line snippet.
- **HTTP Payload Limit**: Maximum 1 MiB JSON request body limit (returns `413 Payload Too Large`).

---

## 9. Running Tests

The test suite runs using Node's native test runner (`node:test`), requiring no external test runner dependencies.

### Run All Tests
```powershell
npm test
```

### Run Tests by Category
```powershell
# 1. Security & Workspace Isolation Tests
node --test tests/security.test.js

# 2. Authentication & Host Validation Tests
node --test tests/auth.test.js

# 3. MCP Functional Tools Tests
node --test tests/tools.test.js

# 4. Stability, Payloads & Lifecycle Tests
node --test tests/stability.test.js
```

---

## 10. Troubleshooting

| Symptom | Likely Cause | Resolution |
|---|---|---|
| HTTP 401 Unauthorized | Missing or incorrect Bearer token | Ensure `Authorization: Bearer <token>` header matches the server's configured token exactly. |
| HTTP 403 Forbidden | Request Host or Origin header is not loopback | The server rejects external hostnames. Use `127.0.0.1` or `localhost`. |
| HTTP 404 Not Found | Incorrect endpoint URL | Ensure requests target `/mcp` (e.g., `http://127.0.0.1:8765/mcp`). |
| `EADDRINUSE` on startup | Port is already occupied | Set another port via `-p <port>` or use port `0` for an OS-assigned dynamic port. |
| "TrueForge blocked the local MCP URL" | Outbound host restriction in TrueForge | Set `$env:OUTBOUND_URL_ALLOWED_HOSTS = '["127.0.0.1"]'` and restart TrueForge. |
| Tool returns "This generated or sensitive path is excluded" | Attempt to access `.env`, `.git`, or key files | By design, sensitive and generated directories are completely inaccessible. |
| Tool returns "File exceeds the 1 MiB read limit" | File is too large | Break the file into smaller modules or use targeted search queries instead. |
