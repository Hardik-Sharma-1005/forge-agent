/**
 * Permanent MCP Workspace Server — Tool Registration
 *
 * Implements the 4 required read-only workspace tools:
 * 1. get_workspace_context
 * 2. list_files
 * 3. read_file
 * 4. search_files
 */

const path = require('path');
const fs = require('fs/promises');
const {
  TOOL_NAMES,
  resolveWorkspaceRoot,
  resolveInside,
  listDirectory,
  readWorkspaceFile,
  searchWorkspaceFiles,
  getWorkspaceContext
} = require('./security');

const READ_ONLY_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
});

/**
 * Creates and registers the 4 workspace tools onto an McpServer instance.
 *
 * @param {object} params
 * @param {typeof import('@modelcontextprotocol/sdk/server/mcp.js').McpServer} params.McpServer
 * @param {typeof import('zod').z} params.z
 * @param {string|Function} params.workspaceRoot - Path string or function returning root path
 * @param {string} [params.serverName='forge-agent-workspace']
 * @param {string} [params.serverVersion='0.1.0']
 * @returns {import('@modelcontextprotocol/sdk/server/mcp.js').McpServer}
 */
function createWorkspaceMcpServer({
  McpServer,
  z,
  workspaceRoot,
  serverName = 'forge-agent-workspace',
  serverVersion = '0.1.0'
}) {
  const server = new McpServer({
    name: serverName,
    version: serverVersion
  });

  const textResult = data => ({
    content: [{ type: 'text', text: JSON.stringify(data) }]
  });

  // Tool 1: get_workspace_context
  server.registerTool('get_workspace_context', {
    description: 'Return useful workspace information including name, root, top-level entries, detected configuration files, and source file types. Excludes generated and sensitive paths.',
    inputSchema: {},
    annotations: {
      title: 'Workspace context',
      ...READ_ONLY_ANNOTATIONS
    }
  }, async () => {
    const root = await resolveWorkspaceRoot(workspaceRoot);
    const context = await getWorkspaceContext(root);
    return textResult(context);
  });

  // Tool 2: list_files
  server.registerTool('list_files', {
    description: 'List relative workspace paths, excluding generated folders and sensitive files. Symlinked directories are not traversed.',
    inputSchema: {
      path: z.string().optional().describe('Workspace-relative directory; omit to start at the workspace root.'),
      recursive: z.boolean().default(true).describe('Whether to descend into subdirectories.'),
      max_results: z.number().int().min(1).max(500).default(200).describe('Maximum number of returned paths.')
    },
    annotations: {
      title: 'List workspace files',
      ...READ_ONLY_ANNOTATIONS
    }
  }, async ({ path: relativePath = '', recursive = true, max_results = 200 }) => {
    const root = await resolveWorkspaceRoot(workspaceRoot);
    const directory = await resolveInside(root, relativePath);
    const stat = await fs.stat(directory);
    if (!stat.isDirectory()) {
      throw new Error('The requested path is not a directory.');
    }
    const files = await listDirectory(root, directory, recursive, max_results);
    return textResult({
      files,
      truncated: files.length >= max_results
    });
  });

  // Tool 3: read_file
  server.registerTool('read_file', {
    description: 'Read a UTF-8 text file inside the active workspace. Sensitive files, binary files, and files larger than 1 MiB are refused.',
    inputSchema: {
      path: z.string().min(1).describe('Workspace-relative file path.')
    },
    annotations: {
      title: 'Read workspace file',
      ...READ_ONLY_ANNOTATIONS
    }
  }, async ({ path: relativePath }) => {
    const root = await resolveWorkspaceRoot(workspaceRoot);
    const fileResult = await readWorkspaceFile(root, relativePath);
    return textResult(fileResult);
  });

  // Tool 4: search_files
  server.registerTool('search_files', {
    description: 'Search text files in the workspace for a case-insensitive literal string. Skips generated and sensitive files.',
    inputSchema: {
      query: z.string().min(1).max(200).describe('Literal text to find.'),
      path: z.string().optional().describe('Workspace-relative directory to search; omit to search the workspace root.'),
      max_results: z.number().int().min(1).max(100).default(50).describe('Maximum matching lines to return.')
    },
    annotations: {
      title: 'Search workspace files',
      ...READ_ONLY_ANNOTATIONS
    }
  }, async ({ query, path: relativePath = '', max_results = 50 }) => {
    const root = await resolveWorkspaceRoot(workspaceRoot);
    const searchResult = await searchWorkspaceFiles(root, relativePath, query, max_results);
    return textResult(searchResult);
  });

  return server;
}

module.exports = {
  createWorkspaceMcpServer,
  TOOL_NAMES,
  READ_ONLY_ANNOTATIONS
};
