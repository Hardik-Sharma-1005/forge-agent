/**
 * Forge Agent — Temporary MCP Bridge Compatibility Layer
 *
 * Re-exports the permanent MCP workspace server to maintain 100% drop-in
 * compatibility with existing extension code expecting ./temp-mcp-bridge.
 */

module.exports = require('./server');
