/**
 * Server Stability & Edge Cases Test Suite
 *
 * Validates resilience against malformed JSON, oversized payloads,
 * nonexistent files, Unicode filenames, empty directories,
 * server shutdown, restart, and port collision handling.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs/promises');
const os = require('os');
const http = require('http');
const { createPermanentMcpServer } = require('../src/server');

describe('Server Stability & Edge Cases Suite', () => {
  let tempRoot;
  let emptyRoot;
  let serverInstance;
  const TEST_TOKEN = 'stability-test-token-abcdef123456';

  before(async () => {
    tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'forge-stab-ws-'));
    emptyRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'forge-stab-empty-'));

    // Create unicode filename and content
    await fs.writeFile(
      path.join(tempRoot, 'тест-🚀-file.txt'),
      'Unicode content: こんにちは, мир, 🌍!\n',
      'utf8'
    );

    // Create empty subdirectory
    await fs.mkdir(path.join(tempRoot, 'empty-dir'), { recursive: true });

    // Create large file (> 1 MiB)
    await fs.writeFile(
      path.join(tempRoot, 'too-large.txt'),
      Buffer.alloc(1024 * 1024 + 100, 0x61)
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
    if (emptyRoot) await fs.rm(emptyRoot, { recursive: true, force: true });
  });

  describe('Malformed & Oversized Payloads', () => {
    it('returns HTTP 400 on malformed JSON body', async () => {
      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: '{"jsonrpc": "2.0", broken_json...'
      });

      assert.equal(res.status, 400);
      const text = await res.text();
      assert.match(text, /Invalid JSON/);
    });

    it('returns HTTP 413 when request body exceeds 1 MiB limit', async () => {
      const hugeBody = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'search_files',
          arguments: { query: 'x'.repeat(1024 * 1024 + 50) }
        }
      });

      const res = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: hugeBody
      });

      assert.equal(res.status, 413);
      const text = await res.text();
      assert.match(text, /Request body exceeds maximum/);
    });

    it('returns tool schema validation error on invalid parameter types', async () => {
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
          method: 'tools/call',
          params: {
            name: 'list_files',
            arguments: { max_results: 'NOT_A_NUMBER' }
          }
        })
      });

      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.result.isError, true);
    });
  });

  describe('Filesystem Edge Cases', () => {
    it('handles Unicode filenames and characters safely', async () => {
      // List
      const listRes = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'list_files', arguments: { recursive: true } }
        })
      });
      const listJson = await listRes.json();
      const files = JSON.parse(listJson.result.content[0].text).files;
      assert.ok(files.includes('тест-🚀-file.txt'));

      // Read
      const readRes = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'read_file', arguments: { path: 'тест-🚀-file.txt' } }
        })
      });
      const readJson = await readRes.json();
      const content = JSON.parse(readJson.result.content[0].text).content;
      assert.match(content, /こんにちは, мир, 🌍!/);

      // Search
      const searchRes = await fetch(serverInstance.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${serverInstance.port}`
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'search_files', arguments: { query: 'こんにちは' } }
        })
      });
      const searchJson = await searchRes.json();
      const matches = JSON.parse(searchJson.result.content[0].text).matches;
      assert.equal(matches.length, 1);
      assert.equal(matches[0].path, 'тест-🚀-file.txt');
    });

    it('handles empty directories gracefully', async () => {
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
          method: 'tools/call',
          params: { name: 'list_files', arguments: { path: 'empty-dir' } }
        })
      });
      const json = await res.json();
      assert.ok(!json.result.isError);
      const data = JSON.parse(json.result.content[0].text);
      assert.deepEqual(data.files, []);
      assert.equal(data.truncated, false);
    });

    it('handles completely empty workspace directory gracefully', async () => {
      const emptyServer = await createPermanentMcpServer({
        workspaceRoot: emptyRoot,
        token: TEST_TOKEN,
        port: 0
      });

      try {
        const res = await fetch(emptyServer.url, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${TEST_TOKEN}`,
            'Content-Type': 'application/json',
            'Host': `127.0.0.1:${emptyServer.port}`
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'tools/call',
            params: { name: 'get_workspace_context', arguments: {} }
          })
        });

        const json = await res.json();
        assert.ok(!json.result.isError);
        const data = JSON.parse(json.result.content[0].text);
        assert.deepEqual(data.topLevel, []);
        assert.deepEqual(data.configFiles, []);
        assert.deepEqual(data.sourceTypes, []);
      } finally {
        await emptyServer.close();
      }
    });

    it('safely handles nonexistent file reads without crashing', async () => {
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
          method: 'tools/call',
          params: { name: 'read_file', arguments: { path: 'file-does-not-exist.txt' } }
        })
      });

      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.result.isError, true);
      assert.match(json.result.content[0].text, /not found/i);
    });

    it('safely rejects reading files larger than 1 MiB', async () => {
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
          method: 'tools/call',
          params: { name: 'read_file', arguments: { path: 'too-large.txt' } }
        })
      });

      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.result.isError, true);
      assert.match(json.result.content[0].text, /exceeds the 1 MiB read limit/i);
    });
  });

  describe('Lifecycle: Shutdown, Restart & Port Conflicts', () => {
    it('shuts down cleanly and restarts on the same port', async () => {
      const transientServer = await createPermanentMcpServer({
        workspaceRoot: tempRoot,
        token: TEST_TOKEN,
        port: 0
      });
      const assignedPort = transientServer.port;
      assert.ok(assignedPort > 0);

      // Verify it responds
      const ping1 = await fetch(transientServer.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${assignedPort}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });
      assert.equal(ping1.status, 200);

      // Shutdown
      await transientServer.close();

      // Verify connection refused after shutdown
      await assert.rejects(
        () => fetch(`http://127.0.0.1:${assignedPort}/mcp`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${TEST_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
        }),
        /fetch failed|ECONNREFUSED/
      );

      // Restart on the exact same port
      const restartedServer = await createPermanentMcpServer({
        workspaceRoot: tempRoot,
        token: TEST_TOKEN,
        port: assignedPort
      });
      assert.equal(restartedServer.port, assignedPort);

      // Verify it responds again
      const ping2 = await fetch(restartedServer.url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
          'Content-Type': 'application/json',
          'Host': `127.0.0.1:${assignedPort}`
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} })
      });
      assert.equal(ping2.status, 200);

      await restartedServer.close();
    });

    it('rejects startup with clean error when port is already in use', async () => {
      const activePort = serverInstance.port;

      await assert.rejects(
        () => createPermanentMcpServer({
          workspaceRoot: tempRoot,
          token: TEST_TOKEN,
          port: activePort
        }),
        /EADDRINUSE/
      );
    });
  });
});
