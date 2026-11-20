'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const server = require('../src/server');
const adapter = require('../src/temp-mcp-bridge');

 test('compatibility adapter preserves the extension imports', () => {
  assert.equal(adapter.createTemporaryMcpBridge, server.createPermanentMcpServer);
  assert.equal(adapter.registerTemporaryBridge, server.registerPermanentMcpServer);
});

test('TrueForge registration sends header auth, discovers tools, and attaches them to the saved agent', async () => {
  const calls = {};
  const agent = {
    id: 'agent-1',
    name: 'forge-agent',
    description: 'Existing agent description',
    manifest: { model: 'preserve-me', mcpServers: [{ name: 'other-server', enableTools: ['keep'] }, { name: 'forge-agent-temp-workspace', enableTools: ['old'] }] }
  };
  const client = {
    settings: {
      mcpServers: {
        list: async () => ({ data: [] }),
        createOrUpdate: async input => { calls.connector = input.manifest; },
        delete: async name => { calls.deleted = name; }
      }
    },
    agents: {
      list: async () => [agent],
      get: async id => ({ data: agent }),
      update: async (id, input) => { calls.agent = { id, ...input }; }
    },
    mcpServers: {
      listTools: async name => {
        calls.listTools = name;
        return { data: server.TOOL_NAMES.map(toolName => ({ name: toolName })) };
      }
    }
  };

  const result = await server.registerPermanentMcpServer({
    client,
    url: 'http://127.0.0.1:43210/mcp',
    token: 'extension-secret',
    agentName: 'forge-agent'
  });

  assert.equal(calls.connector.name, 'forge-agent-workspace');
  assert.equal(calls.connector.auth.headers.Authorization, 'Bearer extension-secret');
  assert.equal(calls.listTools, 'forge-agent-workspace');
  assert.deepEqual(result.tools, ['get_workspace_context', 'list_files', 'read_file', 'search_files']);
  assert.deepEqual(calls.agent.manifest.mcpServers, [
    { name: 'other-server', enableTools: ['keep'] },
    { name: 'forge-agent-workspace', enableTools: server.TOOL_NAMES, preload: true }
  ]);
  assert.equal(calls.agent.manifest.model, 'preserve-me');
});
