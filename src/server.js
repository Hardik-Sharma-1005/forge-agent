/**
 * Permanent MCP Workspace Server — Server Entrypoint & HTTP Transport
 *
 * Exposes workspace tools via official Model Context Protocol (MCP) Streamable HTTP transport.
 * Enforces loopback-only binding, timing-safe Bearer token authentication,
 * host/origin validation, and resource limits.
 */

const http = require('http');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const { createWorkspaceMcpServer, TOOL_NAMES } = require('./tools');
const { resolveWorkspaceRoot } = require('./security');

const SERVER_NAME = 'forge-agent-workspace';
const SERVER_DESCRIPTION = 'Permanent local read-only workspace tools for Forge Agent.';
const DEFAULT_VERSION = '0.1.0';
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB

/**
 * Timing-safe comparison of the supplied token against the expected Bearer token.
 * @param {string|null|undefined} suppliedToken
 * @param {string} expectedToken
 * @returns {boolean}
 */
function authorized(suppliedToken, expectedToken) {
  if (!suppliedToken || typeof suppliedToken !== 'string' || !expectedToken || typeof expectedToken !== 'string') {
    return false;
  }
  const supplied = Buffer.from(suppliedToken.trim(), 'utf8');
  const expected = Buffer.from(expectedToken.trim(), 'utf8');
  if (supplied.length !== expected.length) return false;
  return crypto.timingSafeEqual(supplied, expected);
}

/**
 * Extracts authentication token from the Authorization header or URL query parameters.
 * @param {import('http').IncomingMessage} req
 * @param {URL} url
 * @returns {string|null}
 */
function extractToken(req, url) {
  const header = req.headers.authorization;
  if (header && typeof header === 'string') {
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    if (match) return match[1];
  }
  if (url && url.searchParams) {
    const qToken = url.searchParams.get('token');
    if (qToken && qToken.trim()) return qToken.trim();
  }
  return null;
}

/**
 * Sends an HTML response.
 */
function sendHtml(res, status, html, headers = {}) {
  if (res.headersSent) return;
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(html);
}

/**
 * Renders the HTML Dashboard for direct browser viewing.
 */
function renderDashboardHtml({ serverName, serverVersion, workspaceRoot, port, token }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forge Agent — MCP Workspace Server</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #ffffff;
      --accent: #58a6ff;
      --green: #3fb950;
      --code-bg: #030407;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 30px 20px;
      display: flex;
      justify-content: center;
    }
    .container {
      max-width: 800px;
      width: 100%;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    h1 {
      color: var(--text-bright);
      margin: 0;
      font-size: 1.4rem;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(63, 185, 80, 0.15);
      color: var(--green);
      font-size: 0.8rem;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 12px;
      border: 1px solid rgba(63, 185, 80, 0.3);
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .card h2 {
      color: var(--text-bright);
      font-size: 1.1rem;
      margin-top: 0;
      margin-bottom: 12px;
    }
    .grid {
      display: grid;
      grid-template-columns: 140px 1fr;
      row-gap: 10px;
      font-size: 0.9rem;
    }
    .label {
      color: #8b949e;
      font-weight: 500;
    }
    .value {
      color: var(--text-bright);
      word-break: break-all;
      font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
    }
    .tool-list {
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .tool-item {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .tool-name {
      color: var(--accent);
      font-family: monospace;
      font-weight: 600;
    }
    .tool-desc {
      font-size: 0.85rem;
      color: #8b949e;
      margin-top: 4px;
    }
    button {
      background: #238636;
      color: #fff;
      border: 0;
      border-radius: 6px;
      padding: 6px 12px;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      transition: background 0.2s;
    }
    button:hover {
      background: #2ea043;
    }
    pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 0.85rem;
      color: #38bdf8;
      max-height: 250px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Forge Agent MCP Server</h1>
      <span class="badge">● ONLINE</span>
    </div>

    <div class="card">
      <h2>Server Details</h2>
      <div class="grid">
        <div class="label">Status:</div>
        <div class="value" style="color: var(--green);">Ready for TrueForge & VS Code</div>
        <div class="label">Loopback Endpoint:</div>
        <div class="value">http://127.0.0.1:${port}/mcp</div>
        <div class="label">Transport:</div>
        <div class="value">Streamable HTTP (JSON-RPC)</div>
        <div class="label">Active Workspace:</div>
        <div class="value">${workspaceRoot}</div>
        <div class="label">Authentication:</div>
        <div class="value">Bearer Token (Active)</div>
      </div>
    </div>

    <div class="card">
      <h2>Registered MCP Tools (4)</h2>
      <ul class="tool-list">
        <li class="tool-item">
          <div>
            <div class="tool-name">get_workspace_context</div>
            <div class="tool-desc">Returns workspace name, top-level visible files, detected configs, and source types.</div>
          </div>
          <button onclick="runTool('get_workspace_context', {})">Run in Browser</button>
        </li>
        <li class="tool-item">
          <div>
            <div class="tool-name">list_files</div>
            <div class="tool-desc">Lists workspace files recursively, omitting sensitive directories and files.</div>
          </div>
          <button onclick="runTool('list_files', { recursive: false, max_results: 20 })">Run in Browser</button>
        </li>
        <li class="tool-item">
          <div>
            <div class="tool-name">read_file</div>
            <div class="tool-desc">Reads a UTF-8 workspace file (up to 1 MiB). Rejects sensitive/binary files.</div>
          </div>
          <button onclick="runTool('read_file', { path: 'README.md' })">Read README.md</button>
        </li>
        <li class="tool-item">
          <div>
            <div class="tool-name">search_files</div>
            <div class="tool-desc">Searches text files for case-insensitive literal matches with line numbers.</div>
          </div>
          <button onclick="runTool('search_files', { query: 'Forge' })">Search "Forge"</button>
        </li>
      </ul>

      <div id="output-box" style="margin-top: 16px; display: none;">
        <h3 style="font-size: 0.95rem; margin-bottom: 6px; color: var(--text-bright);">Live Response:</h3>
        <pre id="output"></pre>
      </div>
    </div>
  </div>

  <script>
    const TOKEN = "${token}";
    async function runTool(name, args) {
      const box = document.getElementById('output-box');
      const out = document.getElementById('output');
      box.style.display = 'block';
      out.textContent = 'Executing ' + name + '...';

      try {
        const res = await fetch('/mcp', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + TOKEN
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: Date.now(),
            method: 'tools/call',
            params: { name, arguments: args }
          })
        });
        const data = await res.json();
        if (data.result && data.result.content && data.result.content[0]) {
          try {
            const parsed = JSON.parse(data.result.content[0].text);
            out.textContent = JSON.stringify(parsed, null, 2);
          } catch {
            out.textContent = data.result.content[0].text;
          }
        } else {
          out.textContent = JSON.stringify(data, null, 2);
        }
      } catch (err) {
        out.textContent = 'Error: ' + err.message;
      }
    }
  </script>
</body>
</html>`;
}

/**
 * Renders the HTML login/prompt page when a browser opens without a token.
 */
function renderAuthPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Unauthorized — Forge Agent</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 90vh;
      margin: 0;
    }
    .box {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 30px;
      max-width: 440px;
      width: 100%;
      text-align: center;
    }
    h2 { color: #f85149; margin-top: 0; }
    p { font-size: 0.9rem; color: #8b949e; line-height: 1.5; }
    input {
      width: 90%;
      background: #0d1117;
      border: 1px solid #30363d;
      color: #fff;
      padding: 10px;
      border-radius: 6px;
      margin: 14px 0;
      font-size: 0.9rem;
    }
    button {
      background: #238636;
      color: #fff;
      border: 0;
      border-radius: 6px;
      padding: 10px 18px;
      cursor: pointer;
      font-weight: 600;
    }
    button:hover { background: #2ea043; }
  </style>
</head>
<body>
  <div class="box">
    <h2>🔒 Authentication Required</h2>
    <p>This MCP server requires a Bearer token. Enter your token below or open the server link containing <code>?token=&lt;token&gt;</code>.</p>
    <form onsubmit="event.preventDefault(); window.location.href = '/?token=' + encodeURIComponent(document.getElementById('tok').value.trim());">
      <input type="text" id="tok" placeholder="Paste your Bearer token here..." required autocomplete="off">
      <br>
      <button type="submit">Unlock Dashboard</button>
    </form>
  </div>
</body>
</html>`;
}

/**
 * Validates that the Host header matches loopback on the server's listening port.
 * @param {string|undefined} host
 * @param {number} port
 * @returns {boolean}
 */
function validHost(host, port) {
  if (!host || typeof host !== 'string') return false;
  const lower = host.trim().toLowerCase();
  return lower === `127.0.0.1:${port}` || lower === `localhost:${port}`;
}

/**
 * Validates that the Origin header (if present) matches loopback.
 * @param {string|undefined} origin
 * @param {number} port
 * @returns {boolean}
 */
function validOrigin(origin, port) {
  if (!origin) return true; // Non-browser clients omit Origin
  try {
    const url = new URL(origin);
    const validHosts = new Set(['127.0.0.1', 'localhost']);
    if (!validHosts.has(url.hostname.toLowerCase())) return false;
    const originPort = url.port || (url.protocol === 'https:' ? '443' : '80');
    return String(originPort) === String(port);
  } catch {
    return false;
  }
}

/**
 * Sends a plain-text HTTP response with security headers.
 */
function send(res, status, message, headers = {}) {
  if (res.headersSent) return;
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(message);
}

/**
 * Safely buffers and parses a JSON request body with byte limit enforcement.
 * @param {import('http').IncomingMessage} req
 * @param {number} maxBytes
 * @returns {Promise<any>}
 */
function readJson(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let text = '';
    let bytesReceived = 0;
    let rejected = false;

    req.setEncoding('utf8');
    req.on('data', chunk => {
      if (rejected) return;
      bytesReceived += Buffer.byteLength(chunk);
      if (bytesReceived > maxBytes) {
        rejected = true;
        const err = new Error('Request body exceeds maximum allowed size (1 MiB).');
        err.statusCode = 413;
        reject(err);
        return;
      }
      text += chunk;
    });

    req.on('end', () => {
      if (rejected) return;
      if (!text.trim()) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(text));
      } catch {
        const err = new Error('Invalid JSON body.');
        err.statusCode = 400;
        reject(err);
      }
    });

    req.on('error', reject);
  });
}

/**
 * Starts a permanent MCP workspace server bound exclusively to loopback.
 *
 * @param {object} options
 * @param {string|Function} options.workspaceRoot - Path string or async function returning path
 * @param {string} [options.token] - Bearer token; generated if omitted
 * @param {number} [options.port=0] - Port number (0 for OS-assigned)
 * @param {string} [options.serverName='forge-agent-workspace']
 * @param {string} [options.serverVersion='0.1.0']
 * @returns {Promise<{ url: string, port: number, token: string, close: () => Promise<void> }>}
 */
async function createPermanentMcpServer({
  workspaceRoot,
  token,
  port = 0,
  serverName = SERVER_NAME,
  serverVersion = DEFAULT_VERSION
}) {
  if (!workspaceRoot) {
    throw new Error('A workspaceRoot path or resolver function is required.');
  }

  // Pre-validate workspace root resolution
  await resolveWorkspaceRoot(workspaceRoot);

  const serverToken = token && typeof token === 'string' && token.trim()
    ? token.trim()
    : crypto.randomBytes(32).toString('hex');

  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { StreamableHTTPServerTransport } = await import('@modelcontextprotocol/sdk/server/streamableHttp.js');
  const { z } = await import('zod');

  let listenPort = port;

  const server = http.createServer(async (req, res) => {
    const requestUrl = new URL(req.url || '/', 'http://127.0.0.1');

    // Allow /mcp and / (root dashboard)
    if (requestUrl.pathname !== '/mcp' && requestUrl.pathname !== '/') {
      return send(res, 404, 'Not found');
    }

    // Host header validation (DNS rebinding protection)
    if (!validHost(req.headers.host, listenPort)) {
      return send(res, 403, 'Forbidden: Host header must be loopback (127.0.0.1 or localhost).');
    }

    // Origin header validation (CSRF protection)
    if (!validOrigin(req.headers.origin, listenPort)) {
      return send(res, 403, 'Forbidden: Origin must be loopback.');
    }

    // Token extraction (Authorization header or ?token= query parameter)
    const suppliedToken = extractToken(req, requestUrl);

    // Authentication check
    if (!authorized(suppliedToken, serverToken)) {
      if (req.headers.accept && req.headers.accept.includes('text/html')) {
        return sendHtml(res, 401, renderAuthPage(), { 'WWW-Authenticate': 'Bearer' });
      }
      return send(res, 401, 'Unauthorized', { 'WWW-Authenticate': 'Bearer' });
    }

    // Direct browser GET navigation: render interactive dashboard
    if (req.method === 'GET' && (req.headers.accept?.includes('text/html') || requestUrl.pathname === '/')) {
      return sendHtml(res, 200, renderDashboardHtml({
        serverName,
        serverVersion,
        workspaceRoot: path.resolve(typeof workspaceRoot === 'function' ? 'Dynamic' : workspaceRoot),
        port: listenPort,
        token: serverToken
      }));
    }

    // Normalize Accept header for official MCP SDK compatibility
    if (!req.headers.accept || !req.headers.accept.includes('text/event-stream')) {
      req.headers.accept = 'application/json, text/event-stream';
    }

    let body;
    if (req.method === 'POST') {
      try {
        body = await readJson(req);
      } catch (error) {
        return send(res, error.statusCode || 400, error.message || 'Invalid JSON');
      }
    }

    const mcp = createWorkspaceMcpServer({
      McpServer,
      z,
      workspaceRoot,
      serverName,
      serverVersion
    });

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      if (!res.headersSent) {
        send(res, 500, 'MCP request failed');
      } else {
        res.destroy(error);
      }
    } finally {
      await mcp.close().catch(() => {});
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });

  const address = server.address();
  listenPort = address.port;

  return {
    url: `http://127.0.0.1:${listenPort}/mcp`,
    port: listenPort,
    token: serverToken,
    close: () => new Promise(resolve => {
      server.close(() => resolve());
      server.closeAllConnections();
    })
  };
}

/**
 * Registers the permanent MCP server as a remote connector on TrueForge and updates the agent.
 * Drop-in replacement for registerTemporaryBridge.
 *
 * @param {object} params
 * @param {any} params.client - TrueForge SDK client instance
 * @param {string} params.url - MCP server URL
 * @param {string} params.token - Bearer token
 * @param {string} params.agentName - Target TrueForge agent name
 * @param {string} [params.serverName='forge-agent-workspace'] - Connector name
 * @returns {Promise<{ serverName: string, agentName: string, tools: string[] }>}
 */
async function registerPermanentMcpServer({
  client,
  url,
  token,
  agentName,
  serverName = SERVER_NAME
}) {
  const configured = (await client.settings.mcpServers.list()).data || [];
  const existing = configured.find(s => s.name === serverName);

  const agentPage = await client.agents.list();
  let summary;
  for await (const agent of agentPage) {
    if (agent.name === agentName) {
      summary = agent;
      break;
    }
  }
  if (!summary) {
    throw new Error(`No saved TrueForge agent named “${agentName}” was found.`);
  }

  const { data: agent } = await client.agents.get(summary.id);

  await client.settings.mcpServers.createOrUpdate({
    manifest: {
      name: serverName,
      type: 'remote',
      url,
      description: SERVER_DESCRIPTION,
      auth: {
        type: 'header',
        headers: { Authorization: `Bearer ${token}` }
      }
    }
  });

  try {
    const tools = (await client.mcpServers.listTools(serverName)).data || [];
    const missing = TOOL_NAMES.filter(name => !tools.some(t => t.name === name));
    if (missing.length) {
      throw new Error(`TrueForge reached the server, but tools were missing: ${missing.join(', ')}.`);
    }

    const previousServers = agent.manifest.mcpServers || [];
    const nextServers = [
      ...previousServers.filter(item => item.name !== serverName && item.name !== 'forge-agent-temp-workspace'),
      { name: serverName, enableTools: TOOL_NAMES, preload: true }
    ];

    await client.agents.update(agent.id, {
      description: agent.description,
      manifest: { ...agent.manifest, mcpServers: nextServers }
    });
  } catch (error) {
    if (!existing) {
      await client.settings.mcpServers.delete(serverName).catch(() => {});
    }
    throw error;
  }

  return { serverName, agentName: agent.name, tools: TOOL_NAMES };
}

// CLI entrypoint
if (require.main === module) {
  (async () => {
    const args = process.argv.slice(2);
    let workspaceRoot = process.env.FORGE_WORKSPACE_ROOT || process.cwd();
    let port = parseInt(process.env.FORGE_MCP_PORT || '8765', 10);
    let token = process.env.FORGE_MCP_TOKEN;
    let tokenFile = null;

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '--workspace' || arg === '-w') {
        workspaceRoot = args[++i];
      } else if (arg === '--port' || arg === '-p') {
        port = parseInt(args[++i], 10);
      } else if (arg === '--token' || arg === '-t') {
        token = args[++i];
      } else if (arg === '--token-file') {
        tokenFile = args[++i];
      } else if (arg === '--help' || arg === '-h') {
        console.log(`Forge Agent — Permanent MCP Workspace Server
Usage:
  node src/server.js [options]

Options:
  -w, --workspace <path>  Workspace root directory (default: current directory or FORGE_WORKSPACE_ROOT)
  -p, --port <number>     Port to bind on 127.0.0.1 (default: 8765 or FORGE_MCP_PORT, 0 for dynamic)
  -t, --token <string>    Bearer authentication token (default: FORGE_MCP_TOKEN or random)
      --token-file <path> Write generated Bearer token to file with restricted permissions
  -h, --help              Show this help message
`);
        process.exit(0);
      }
    }

    try {
      const serverInstance = await createPermanentMcpServer({
        workspaceRoot,
        token,
        port
      });

      console.log(`[forge-mcp-server] Server running at: ${serverInstance.url}`);
      console.log(`[forge-mcp-server] Workspace root: ${path.resolve(workspaceRoot)}`);
      console.log(`[forge-mcp-server] Bound exclusively to loopback (127.0.0.1:${serverInstance.port})`);
      console.log(`[forge-mcp-server] Tools: ${TOOL_NAMES.join(', ')}`);
      console.log(`[forge-mcp-server] Authentication: Bearer token required`);

      if (tokenFile) {
        await fs.writeFile(path.resolve(tokenFile), serverInstance.token, { encoding: 'utf8', mode: 0o600 });
        console.log(`[forge-mcp-server] Bearer token written to ${tokenFile}`);
      }

      const shutdown = async () => {
        console.log('\n[forge-mcp-server] Shutting down server...');
        await serverInstance.close();
        process.exit(0);
      };

      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
    } catch (err) {
      console.error(`[forge-mcp-server] Startup error: ${err.message}`);
      process.exit(1);
    }
  })();
}

module.exports = {
  createPermanentMcpServer,
  registerPermanentMcpServer,
  // Drop-in compatibility aliases for existing extension code
  createTemporaryMcpBridge: createPermanentMcpServer,
  registerTemporaryBridge: registerPermanentMcpServer,
  TOOL_NAMES,
  SERVER_NAME,
  SERVER_DESCRIPTION
};
