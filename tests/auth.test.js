/**
 * Authentication & Network Security Test Suite
 *
 * Validates Bearer token authentication, timing safety, 401 responses,
 * Host header checking, Origin validation, loopback restriction, and path routing.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');
const { createPermanentMcpServer } = require('../src/server');

describe('Authentication & Network Security', () => {
  let tempRoot;
  let serverInstance;
  const TEST_TOKEN = 'test-secret-token-abcdef1234567890';

  before(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'forge-auth-ws-'));
    await fs.writeFile(path.join(tempRoot, 'README.md'), '# Auth Test Workspace\n', 'utf8');

    serverInstance = await createPermanentMcpServer({
      workspaceRoot: tempRoot,
      token: TEST_TOKEN,
      port: 0
    });
  });

  after(async () => {
    if (serverInstance) await serverInstance.close();
    if (tempRoot) await fs.rm(tempRoot, { recursive: true, force: true });
  });

  describe('Loopback Binding', () => {
    it('binds the listening socket exclusively to IPv4 loopback', () => {
      assert.equal(serverInstance.address.address, '127.0.0.1');
      assert.equal(serverInstance.address.family, 'IPv4');
    });
  });
  describe('HTTP Bearer Token Authentication', () => {
    it('returns HTTP 401 when Authorization header is completely missing', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });

      assert.equal(res.status, 401);
      assert.equal(res.headers.get('WWW-Authenticate'), 'Bearer');
      const text = await res.text();
      assert.equal(text, 'Unauthorized');
    });

    it('returns HTTP 401 when Authorization header has wrong scheme (Basic)', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': 'Basic dXNlcjpwYXNz',
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });

      assert.equal(res.status, 401);
      assert.equal(res.headers.get('WWW-Authenticate'), 'Bearer');
    });

    it('rejects a valid token supplied only in the query string', async () => {
      const url = new URL(serverInstance.url);
      url.searchParams.set('token', TEST_TOKEN);
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Host': `127.0.0.1:${serverInstance.port}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });
      assert.equal(res.status, 401);
      assert.equal(res.headers.get('WWW-Authenticate'), 'Bearer');
    });
    it('returns HTTP 401 when Bearer token is invalid', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer wrong-token-12345',
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });

      assert.equal(res.status, 401);
      assert.equal(res.headers.get('WWW-Authenticate'), 'Bearer');
    });

    it('returns HTTP 401 when token is a prefix or different length', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN.slice(0, 10)}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });

      assert.equal(res.status, 401);
    });

    it('accepts valid Bearer token and returns HTTP 200 for MCP JSON-RPC', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          params: {}
        })
      });

      assert.equal(res.status, 200);
      const json = await res.json();
      assert.ok(json.result);
      assert.ok(Array.isArray(json.result.tools));
      assert.equal(json.result.tools.length, 4);
    });
  });

  describe('Host & Origin Protection', () => {
    it('rejects external/spoofed Host header with HTTP 403', async () => {
      const http = require('http');
      const response = await new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: serverInstance.port,
          path: '/mcp',
          method: 'POST',
          headers: {
            'Host': `attacker.com:${serverInstance.port}`,
            'Authorization': `Bearer ${TEST_TOKEN}`,
            'Content-Type': 'application/json'
          }
        }, res => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve({ status: res.statusCode, text: data }));
        });
        req.on('error', reject);
        req.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }));
        req.end();
      });

      assert.equal(response.status, 403);
      assert.match(response.text, /Forbidden: Host header must be loopback/);
    });

    it('rejects malicious external Origin header with HTTP 403', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`,
          'Origin': 'https://evil-website.com'
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });

      assert.equal(res.status, 403);
      const text = await res.text();
      assert.match(text, /Forbidden: Origin must be loopback/);
    });

    it('accepts loopback origin (http://localhost:<port>)', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`,
          'Origin': `http://localhost:${serverInstance.port}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });

      assert.equal(res.status, 200);
    });
  });

  describe('Endpoint & Route Security', () => {
    it('returns HTTP 404 for unknown routes', async () => {
      const res = await fetch(`http://127.0.0.1:${serverInstance.port}/unknown-endpoint`, {
        method: 'GET',
        headers: {
          'Host': `127.0.0.1:${serverInstance.port}`
        }
      });

      assert.equal(res.status, 404);
    });

    it('requires Bearer authentication on every valid route (no unauthenticated backdoors)', async () => {
      const res = await fetch(`http://127.0.0.1:${serverInstance.port}/mcp`, {
        method: 'GET',
        headers: {
          'Host': `127.0.0.1:${serverInstance.port}`
        }
      });

      assert.equal(res.status, 401);
    });
  });
});
