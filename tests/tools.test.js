/**
 * MCP Tools Functional Test Suite
 *
 * Validates official MCP initialization, tool discovery, and execution
 * of all four tools: get_workspace_context, list_files, read_file, search_files.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');
const { createPermanentMcpServer } = require('../src/server');

describe('MCP Functional Tools Suite', () => {
  let tempRoot;
  let serverInstance;
  const TEST_TOKEN = 'tools-test-token-0123456789abcdef';

  before(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'forge-tools-ws-'));

    // Create project structure
    await fs.mkdir(path.join(tempRoot, 'src', 'utils'), { recursive: true });
    await fs.mkdir(path.join(tempRoot, 'docs'), { recursive: true });

    await fs.writeFile(
      path.join(tempRoot, 'package.json'),
      JSON.stringify({ name: 'functional-test-app', version: '1.0.0' }, null, 2),
      'utf8'
    );
    await fs.writeFile(
      path.join(tempRoot, 'src', 'index.js'),
      'const helper = require("./utils/helper");\nconsole.log("App started");\n',
      'utf8'
    );
    await fs.writeFile(
      path.join(tempRoot, 'src', 'utils', 'helper.js'),
      'function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n',
      'utf8'
    );
    await fs.writeFile(
      path.join(tempRoot, 'docs', 'guide.md'),
      '# User Guide\nWelcome to functional test application.\n',
      'utf8'
    );

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

  /**
   * Helper to perform authenticated JSON-RPC calls
   */
  async function rpc(method, params = {}) {
    const res = await fetch(serverInstance.url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${TEST_TOKEN}`,
        'Content-Type': 'application/json',
        'Host': `127.0.0.1:${serverInstance.port}`
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Math.floor(Math.random() * 100000),
        method,
        params
      })
    });

    assert.equal(res.status, 200, `Expected 200, got ${res.status}`);
    const json = await res.json();
    return json;
  }

  describe('MCP Lifecycle & Tool Discovery', () => {
    it('handles initialize handshake with server metadata', async () => {
      const res = await rpc('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test-client', version: '1.0.0' }
      });

      assert.ok(res.result);
      assert.equal(res.result.serverInfo.name, 'forge-agent-workspace');
      assert.equal(res.result.serverInfo.version, '0.1.0');
      assert.ok(res.result.protocolVersion);
    });

    it('discovers all 4 workspace tools with correct schemas', async () => {
      const res = await rpc('tools/list', {});
      assert.ok(res.result);
      assert.ok(Array.isArray(res.result.tools));

      const toolNames = res.result.tools.map(t => t.name);
      assert.deepEqual(toolNames.sort(), [
        'get_workspace_context',
        'list_files',
        'read_file',
        'search_files'
      ].sort());

      for (const tool of res.result.tools) {
        assert.ok(tool.description, `Tool ${tool.name} must have a description`);
        assert.ok(tool.inputSchema, `Tool ${tool.name} must have an inputSchema`);
      }
    });
  });

  describe('Tool: get_workspace_context', () => {
    it('returns workspace root, name, topLevel, configFiles, and sourceTypes', async () => {
      const res = await rpc('tools/call', {
        name: 'get_workspace_context',
        arguments: {}
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      assert.equal(res.result.content[0].type, 'text');

      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.name, path.basename(tempRoot));
      assert.equal(data.root, await fs.realpath(tempRoot));
      assert.ok(Array.isArray(data.topLevel));
      assert.ok(data.topLevel.includes('package.json'));
      assert.ok(data.topLevel.includes('src/'));
      assert.ok(data.topLevel.includes('docs/'));
      assert.deepEqual(data.availableTools, [
        'get_workspace_context',
        'list_files',
        'read_file',
        'search_files'
      ]);
      assert.ok(data.configFiles.includes('package.json'));
      assert.ok(data.sourceTypes.includes('.js'));
      assert.ok(data.sourceTypes.includes('.md'));
      assert.equal(data.structureSummary.directories, 2);
      assert.equal(data.structureSummary.files, 1);
    });
  });

  describe('Tool: list_files', () => {
    it('lists all workspace files recursively', async () => {
      const res = await rpc('tools/call', {
        name: 'list_files',
        arguments: { recursive: true }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.ok(Array.isArray(data.files));
      assert.equal(data.truncated, false);

      assert.ok(data.files.includes('package.json'));
      assert.ok(data.files.includes('src/index.js'));
      assert.ok(data.files.includes('src/utils/helper.js'));
      assert.ok(data.files.includes('docs/guide.md'));
    });

    it('lists a specific subdirectory', async () => {
      const res = await rpc('tools/call', {
        name: 'list_files',
        arguments: { path: 'src', recursive: true }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.ok(data.files.includes('src/index.js'));
      assert.ok(data.files.includes('src/utils/helper.js'));
      assert.ok(!data.files.includes('docs/guide.md'));
    });

    it('respects max_results limit and sets truncated flag', async () => {
      const res = await rpc('tools/call', {
        name: 'list_files',
        arguments: { max_results: 2 }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.files.length, 2);
      assert.equal(data.truncated, true);
    });
  });

  describe('Tool: read_file', () => {
    it('reads a valid UTF-8 file inside the workspace', async () => {
      const res = await rpc('tools/call', {
        name: 'read_file',
        arguments: { path: 'src/index.js' }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.path, 'src/index.js');
      assert.match(data.content, /App started/);
    });

    it('returns an error when reading a nonexistent file', async () => {
      const res = await rpc('tools/call', {
        name: 'read_file',
        arguments: { path: 'nonexistent.txt' }
      });

      assert.ok(res.result);
      assert.equal(res.result.isError, true);
      assert.match(res.result.content[0].text, /not found/i);
    });

    it('returns an error when attempting path traversal in read_file', async () => {
      const res = await rpc('tools/call', {
        name: 'read_file',
        arguments: { path: '../../package.json' }
      });

      assert.ok(res.result);
      assert.equal(res.result.isError, true);
      assert.match(res.result.content[0].text, /traversal|escapes/i);
    });
  });

  describe('Tool: search_files', () => {
    it('finds literal text matches across workspace files with line numbers', async () => {
      const res = await rpc('tools/call', {
        name: 'search_files',
        arguments: { query: 'App started' }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.matches.length, 1);
      assert.equal(data.matches[0].path, 'src/index.js');
      assert.equal(data.matches[0].line, 2);
      assert.match(data.matches[0].text, /App started/);
    });

    it('performs case-insensitive searches', async () => {
      const res = await rpc('tools/call', {
        name: 'search_files',
        arguments: { query: 'app STARTED' }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.matches.length, 1);
      assert.equal(data.matches[0].path, 'src/index.js');
    });

    it('restricts search to a specific directory', async () => {
      const res = await rpc('tools/call', {
        name: 'search_files',
        arguments: { query: 'function', path: 'src/utils' }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.matches.length, 1);
      assert.equal(data.matches[0].path, 'src/utils/helper.js');
    });

    it('respects max_results limit', async () => {
      const res = await rpc('tools/call', {
        name: 'search_files',
        arguments: { query: 'e', max_results: 1 }
      });

      assert.ok(res.result);
      assert.ok(!res.result.isError);
      const data = JSON.parse(res.result.content[0].text);
      assert.equal(data.matches.length, 1);
      assert.equal(data.truncated, true);
    });
  });
});
