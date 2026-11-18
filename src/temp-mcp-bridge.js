const http = require('http');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

const TOOL_NAMES = ['get_workspace_context', 'list_files', 'read_file', 'search_files'];
const OMIT_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', 'out', 'target', 'coverage', '.next', '.nuxt', '.turbo', '.cache', '.parcel-cache', '.venv', 'venv', '__pycache__', 'vendor', '.aws', '.ssh', '.gnupg', '.azure', '.kube']);
const OMIT_FILES = new Set(['.npmrc', '.pypirc', '.netrc', '.git-credentials', 'id_rsa', 'id_ed25519', 'known_hosts']);
const OMIT_EXTENSIONS = new Set(['.pem', '.key', '.p12', '.pfx', '.p7b', '.p7c', '.p8', '.jks', '.keystore', '.crt', '.cer']);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_SEARCH_FILES = 500;
const MAX_SEARCH_BYTES = 20 * 1024 * 1024;
const SERVER_NAME = 'forge-agent-temp-workspace';
const SERVER_DESCRIPTION = 'Temporary local read-only workspace tools for Forge Agent; replace with Daksh’s permanent MCP server when ready.';

async function registerTemporaryBridge({ client, url, token, agentName }) {
  const configured = (await client.settings.mcpServers.list()).data || [];
  const existing = configured.find(server => server.name === SERVER_NAME);
  if (existing && !String(existing.manifest?.description || '').startsWith('Temporary local read-only workspace tools for Forge Agent')) {
    throw new Error(`A different TrueForge connector already uses “${SERVER_NAME}”; it was left unchanged.`);
  }
  const agentPage = await client.agents.list();
  let summary;
  for await (const agent of agentPage) { if (agent.name === agentName) { summary = agent; break; } }
  if (!summary) throw new Error(`No saved TrueForge agent named “${agentName}” was found.`);
  const { data: agent } = await client.agents.get(summary.id);

  await client.settings.mcpServers.createOrUpdate({ manifest: {
    name: SERVER_NAME,
    type: 'remote',
    url,
    description: SERVER_DESCRIPTION,
    auth: { type: 'header', headers: { Authorization: `Bearer ${token}` } }
  } });
  try {
    const tools = (await client.mcpServers.listTools(SERVER_NAME)).data || [];
    const missing = TOOL_NAMES.filter(name => !tools.some(tool => tool.name === name));
    if (missing.length) throw new Error(`TrueForge reached the bridge, but these tools were missing: ${missing.join(', ')}.`);
    const previousServers = agent.manifest.mcpServers || [];
    const nextServers = [...previousServers.filter(item => item.name !== SERVER_NAME), { name: SERVER_NAME, enableTools: TOOL_NAMES, preload: true }];
    await client.agents.update(agent.id, { description: agent.description, manifest: { ...agent.manifest, mcpServers: nextServers } });
  } catch (error) {
    if (!existing) await client.settings.mcpServers.delete(SERVER_NAME).catch(() => {});
    throw error;
  }
  return { serverName: SERVER_NAME, agentName: agent.name, tools: TOOL_NAMES };
}

async function createTemporaryMcpBridge({ workspaceRoot, token, port = 0 }) {
  if (!token || typeof token !== 'string') throw new Error('A local MCP bearer token is required.');
  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
  const { StreamableHTTPServerTransport } = await import('@modelcontextprotocol/sdk/server/streamableHttp.js');
  const { z } = await import('zod');

  let listenPort = port;
  const server = http.createServer(async (req, res) => {
    const requestUrl = new URL(req.url || '/', 'http://127.0.0.1');
    if (requestUrl.pathname !== '/mcp') return send(res, 404, 'Not found');
    if (!validHost(req.headers.host, listenPort) || !validOrigin(req.headers.origin, listenPort)) return send(res, 403, 'Local requests only');
    if (!authorized(req.headers.authorization, token)) return send(res, 401, 'Unauthorized', { 'WWW-Authenticate': 'Bearer' });

    let body;
    if (req.method === 'POST') {
      try { body = await readJson(req); }
      catch (error) { return send(res, error.statusCode || 400, error.message || 'Invalid JSON'); }
    }
    const mcp = createServer(McpServer, z, workspaceRoot);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      if (!res.headersSent) send(res, 500, 'MCP request failed');
      else res.destroy(error);
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
    url: `http://127.0.0.1:${address.port}/mcp`,
    port: address.port,
    close: () => new Promise(resolve => {
      server.close(() => resolve());
      server.closeAllConnections();
    })
  };
}

function createServer(McpServer, z, workspaceRoot) {
  const server = new McpServer({ name: 'forge-agent-temp-workspace', version: '0.1.0' });
  const readonly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
  const result = data => ({ content: [{ type: 'text', text: JSON.stringify(data) }] });

  server.registerTool('get_workspace_context', {
    description: 'Return the active workspace name, root, and a short list of visible top-level entries. Excludes generated and sensitive paths.',
    inputSchema: {}, annotations: { title: 'Workspace context', ...readonly }
  }, async () => {
    const root = await getRoot(workspaceRoot);
    const names = await listDirectory(root, root, false);
    return result({ name: path.basename(root), root, topLevel: names.slice(0, 80), availableTools: TOOL_NAMES });
  });

  server.registerTool('list_files', {
    description: 'List relative workspace paths, excluding generated folders and sensitive files. Symlinked directories are not traversed.',
    inputSchema: {
      path: z.string().optional().describe('Workspace-relative directory; omit to start at the workspace root.'),
      recursive: z.boolean().default(true).describe('Whether to descend into subdirectories.'),
      max_results: z.number().int().min(1).max(500).default(200).describe('Maximum number of returned paths.')
    }, annotations: { title: 'List workspace files', ...readonly }
  }, async ({ path: relativePath = '', recursive = true, max_results = 200 }) => {
    const root = await getRoot(workspaceRoot);
    const directory = await resolveInside(root, relativePath);
    const stat = await fs.stat(directory);
    if (!stat.isDirectory()) throw new Error('The requested path is not a directory.');
    const files = await listDirectory(root, directory, recursive, max_results);
    return result({ files, truncated: files.length >= max_results });
  });

  server.registerTool('read_file', {
    description: 'Read a UTF-8 text file inside the active workspace. Sensitive files and files larger than 1 MiB are refused.',
    inputSchema: { path: z.string().min(1).describe('Workspace-relative file path.') },
    annotations: { title: 'Read workspace file', ...readonly }
  }, async ({ path: relativePath }) => {
    const root = await getRoot(workspaceRoot);
    const file = await resolveInside(root, relativePath);
    const stat = await fs.stat(file);
    if (!stat.isFile()) throw new Error('The requested path is not a regular file.');
    if (stat.size > MAX_FILE_BYTES) throw new Error('File exceeds the 1 MiB read limit.');
    const bytes = await fs.readFile(file);
    if (bytes.includes(0)) throw new Error('Binary files cannot be read by this tool.');
    return result({ path: path.relative(root, file).split(path.sep).join('/'), content: bytes.toString('utf8') });
  });

  server.registerTool('search_files', {
    description: 'Search text files in the workspace for a case-insensitive literal string. Skips generated and sensitive files.',
    inputSchema: {
      query: z.string().min(1).max(200).describe('Literal text to find.'),
      path: z.string().optional().describe('Workspace-relative directory to search; omit to search the workspace root.'),
      max_results: z.number().int().min(1).max(100).default(50).describe('Maximum matching lines to return.')
    }, annotations: { title: 'Search workspace files', ...readonly }
  }, async ({ query, path: relativePath = '', max_results = 50 }) => {
    const root = await getRoot(workspaceRoot);
    const directory = await resolveInside(root, relativePath);
    const stat = await fs.stat(directory);
    if (!stat.isDirectory()) throw new Error('The requested path is not a directory.');
    const files = await listDirectory(root, directory, true, MAX_SEARCH_FILES);
    const matches = [];
    let bytesRead = 0;
    const needle = query.toLocaleLowerCase();
    for (const relative of files) {
      if (matches.length >= max_results || bytesRead >= MAX_SEARCH_BYTES) break;
      const target = await resolveInside(root, relative);
      const info = await fs.stat(target);
      if (!info.isFile() || info.size > MAX_FILE_BYTES) continue;
      bytesRead += info.size;
      const bytes = await fs.readFile(target);
      if (bytes.includes(0)) continue;
      const lines = bytes.toString('utf8').split(/\r?\n/);
      for (let i = 0; i < lines.length && matches.length < max_results; i++) {
        if (lines[i].toLocaleLowerCase().includes(needle)) matches.push({ path: relative, line: i + 1, text: lines[i].slice(0, 500) });
      }
    }
    return result({ matches, truncated: matches.length >= max_results || files.length >= MAX_SEARCH_FILES || bytesRead >= MAX_SEARCH_BYTES });
  });

  return server;
}

async function getRoot(workspaceRoot) {
  const root = await workspaceRoot();
  if (!root) throw new Error('Open a workspace folder before using workspace tools.');
  return fs.realpath(root);
}

async function resolveInside(root, input) {
  if (typeof input !== 'string' || input.includes('\0')) throw new Error('Invalid workspace-relative path.');
  const normalized = input.replace(/\\/g, '/');
  if (path.posix.isAbsolute(normalized) || path.win32.isAbsolute(input) || /^[a-zA-Z]:/.test(input)) throw new Error('Absolute paths are not allowed.');
  const parts = normalized.split('/').filter(Boolean);
  if (parts.some(part => part === '.' || part === '..' || part.includes(':'))) throw new Error('Path traversal and alternate data streams are not allowed.');
  if (isExcluded(parts)) throw new Error('This generated or sensitive path is excluded.');
  const candidate = path.resolve(root, ...parts);
  const relative = path.relative(root, candidate);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('Path escapes the workspace.');
  const real = await fs.realpath(candidate);
  const realRelative = path.relative(root, real);
  if (realRelative === '..' || realRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realRelative)) throw new Error('Resolved path escapes the workspace.');
  if (isExcluded(realRelative.split(path.sep))) throw new Error('This generated or sensitive path is excluded.');
  return real;
}

function isExcluded(parts) {
  if (parts.some(part => OMIT_DIRS.has(part.toLowerCase()) || part.toLowerCase().startsWith('.env') || /(^|[._-])(secret|secrets|credential|credentials|id_rsa|id_ed25519)([._-]|$)/i.test(part))) return true;
  const name = (parts[parts.length - 1] || '').toLowerCase();
  return OMIT_FILES.has(name) || OMIT_EXTENSIONS.has(path.extname(name));
}

async function listDirectory(root, start, recursive, limit = 500) {
  const found = [];
  async function visit(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (found.length >= limit) return;
      const full = path.join(dir, entry.name);
      const rel = path.relative(root, full);
      if (isExcluded(rel.split(path.sep))) continue;
      if (entry.isSymbolicLink()) continue;
      if (entry.isFile()) found.push(rel.split(path.sep).join('/'));
      else if (entry.isDirectory()) {
        found.push(rel.split(path.sep).join('/') + '/');
        if (recursive) await visit(full);
      }
    }
  }
  await visit(start);
  return found;
}

function validHost(host, port) {
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
}
function validOrigin(origin, port) {
  if (!origin) return true;
  try { const url = new URL(origin); return ['127.0.0.1', 'localhost'].includes(url.hostname) && String(url.port || (url.protocol === 'https:' ? 443 : 80)) === String(port); }
  catch { return false; }
}
function authorized(header, token) {
  const supplied = /^Bearer (.+)$/i.exec(header || '')?.[1];
  if (!supplied) return false;
  const a = Buffer.from(supplied); const b = Buffer.from(token);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function send(res, status, message, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...headers });
  res.end(message);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let text = '';
    let tooLarge = false;
    req.setEncoding('utf8');
    req.on('data', chunk => {
      if (tooLarge) return;
      if (Buffer.byteLength(text) + Buffer.byteLength(chunk) > 1024 * 1024) { tooLarge = true; const error = new Error('Request body is too large.'); error.statusCode = 413; reject(error); return; }
      text += chunk;
    });
    req.on('end', () => {
      if (tooLarge) return;
      try { resolve(text ? JSON.parse(text) : undefined); }
      catch { const error = new Error('Invalid JSON body.'); error.statusCode = 400; reject(error); }
    });
    req.on('error', reject);
  });
}

module.exports = { createTemporaryMcpBridge, registerTemporaryBridge, TOOL_NAMES, SERVER_NAME };
