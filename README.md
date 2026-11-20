# Forge Agent

A small VS Code chat extension that runs agent turns through TrueForge and reviews proposed edits in VS Code's native diff editor.

## Setup

1. Install Node.js 22.14+ and VS Code 1.85+.
2. Start TrueForge and make sure the saved agent named `forge-agent` exists (or set `forgeAgent.agentName` to its name). TrueForge's default outbound URL policy blocks loopback MCP servers. Add `127.0.0.1` to `OUTBOUND_URL_ALLOWED_HOSTS` and restart TrueForge; for a fresh local launch from PowerShell, use `$env:OUTBOUND_URL_ALLOWED_HOSTS='["127.0.0.1"]'` followed by `npx @truefoundry/trueforge`. When this extension activates, it starts the loopback-only workspace server through Daksh's compatibility adapter, registers it as `forge-agent-workspace`, checks its tools through TrueForge, and attaches those four read-only tools to the saved agent without changing its model or other settings. The bridge bearer token is stored in VS Code Secret Storage and sent to TrueForge as connector header auth.
3. In the TrueForge agent instructions, tell the agent to inspect via MCP, never write files directly, and return edits as the shared proposal JSON:

```json
{"proposalId":"unique-id","files":[{"path":"relative/path","operation":"modify","originalContent":"old text","proposedContent":"new text","reason":"why"}]}
```

4. Run `npm install` in this folder.
5. Open this folder in VS Code and press F5 to start the Extension Development Host.
6. Set `forgeAgent.agentName` to the saved agent name. `forgeAgent.baseUrl` defaults to `http://localhost:8790`; set `forgeAgent.token` only for an authenticated TrueForge server.
7. Run **Forge Agent: Open Chat** from the Command Palette. If initial connector setup fails, run **Forge Agent: Connect Temporary MCP Bridge** to retry.

## Chat and edits

The extension uses `@truefoundry/trueforge-sdk` sessions and streamed turn events. Stop asks TrueForge to cancel the active session; if connection fails, remaining client rendering is stopped as well. Conversation history is held in the TrueForge session for the current chat panel.

When the agent returns a proposal, the chat shows a **Review proposed edits** button. You can also run **Forge Agent: Review Edit Proposal** and paste proposal JSON. Each target file is checked against the supplied original content, shown in a native VS Code diff, and written only after you choose **Apply this file**. Proposals currently support modifications to existing workspace files; file creation and deletion are not supported. Multiple files are reviewed one at a time.

The server exposes only the four read-only workspace tools. It binds to `127.0.0.1` on an OS-assigned port, checks a bearer token, rejects paths outside the active workspace (including symlink escapes), and skips common generated folders, credential directories, environment files, private key files, binary files, and oversized files. It does not modify workspace files. Edit review remains in the extension and still requires explicit approval.

## Checks

`npm run check` validates the extension JavaScript syntax. Run `npm install` and launch the extension host for a local integration check with TrueForge.

## Permanent MCP server

Daksh's read-only workspace server is available as `node src/server.js` or `npm start`. It binds to `127.0.0.1`; clients must authenticate with `Authorization: Bearer <token>`. Query-string tokens and the HTML dashboard have been removed. Set `FORGE_MCP_TOKEN` for a chosen token or let the server generate one. The server implements `get_workspace_context`, `list_files`, `read_file`, and `search_files` with path and sensitive-file protections. Run `npm test` and `npm run check` for local validation.

The extension's existing `./temp-mcp-bridge` import is preserved through Daksh's compatibility adapter, which re-exports the permanent server API aliases. The extension's `main`, commands, native diff review, and explicit per-file approval remain in place.
