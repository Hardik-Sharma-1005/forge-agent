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
    if (requestUrl.pathname !== '/mcp') {
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

    // Bearer tokens are accepted only from the Authorization header.
    const suppliedToken = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '')?.[1] || null;

    // Authentication check
    if (!authorized(suppliedToken, serverToken)) {
      return send(res, 401, 'Unauthorized', { 'WWW-Authenticate': 'Bearer' });
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
    address: server.address(),
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
