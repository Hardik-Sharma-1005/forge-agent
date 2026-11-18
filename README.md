# Forge Agent

A small VS Code chat extension that runs agent turns through TrueForge and reviews proposed edits in VS Code's native diff editor.

## Setup

1. Install Node.js 22.14+ and VS Code 1.85+.
2. Start TrueForge and make sure the saved agent named `forge-agent` exists (or set `forgeAgent.agentName` to its name). TrueForge's default outbound URL policy blocks loopback MCP servers. Add `127.0.0.1` to `OUTBOUND_URL_ALLOWED_HOSTS` and restart TrueForge; for a fresh local launch from PowerShell, use `$env:OUTBOUND_URL_ALLOWED_HOSTS='["127.0.0.1"]'` followed by `npx @truefoundry/trueforge`. When this extension activates, it starts a loopback-only MCP bridge, registers it as `forge-agent-temp-workspace`, checks its tools through TrueForge, and attaches those four read-only tools to the saved agent without changing its model or other settings. The bridge bearer token is stored in VS Code Secret Storage and sent to TrueForge as connector header auth.
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

The temporary server exposes only the four read-only workspace tools. It binds to `127.0.0.1` on an OS-assigned port, checks a bearer token, rejects paths outside the active workspace (including symlink escapes), and skips common generated folders, credential directories, environment files, private key files, binary files, and oversized files. It does not modify workspace files. Edit review remains in the extension and still requires explicit approval.

## Replacing the temporary bridge

When Daksh's MCP server is ready, attach its connector to the saved TrueForge agent and remove `forge-agent-temp-workspace` from TrueForge Settings → Connectors. Then remove `src/temp-mcp-bridge.js`, its import/startup and `forgeAgent.connectTemporaryMcpBridge` command from `src/extension.js` / `package.json`, and the `@modelcontextprotocol/sdk` and `zod` dependencies. Keep the `TrueForge` chat SDK dependency and native diff review flow. The extension's agent instructions already tell the agent to use MCP tools for workspace inspection.

The bridge connector record remains in TrueForge if VS Code is closed; its temporary port is no longer serving. The next extension activation refreshes the record and reattaches the bridge. After replacing it with Daksh's server, remove that connector so the stale endpoint is not selected.

## Checks

`npm run check` validates the extension JavaScript syntax. Run `npm install` and launch the extension host for a local integration check with TrueForge.
