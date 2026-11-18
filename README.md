# Forge Agent

A small VS Code chat extension that runs agent turns through TrueForge and reviews proposed edits in VS Code's native diff editor.

## Setup

1. Install Node.js 22.14+ and VS Code 1.85+.
2. In TrueForge, create a saved agent and connect Daksh's MCP workspace server to that agent. Give it workspace inspection tools (`list_files`, `search_files`, `read_file`, `get_workspace_context`) and the `propose_edit` capability when available.
3. In the TrueForge agent instructions, tell the agent to inspect via MCP, never write files directly, and return edits as the shared proposal JSON:

```json
{"proposalId":"unique-id","files":[{"path":"relative/path","operation":"modify","originalContent":"old text","proposedContent":"new text","reason":"why"}]}
```

4. Run `npm install` in this folder.
5. Open this folder in VS Code and press F5 to start the Extension Development Host.
6. Set `forgeAgent.agentName` to the saved agent name. `forgeAgent.baseUrl` defaults to `http://localhost:8790`; set `forgeAgent.token` only for an authenticated TrueForge server.
7. Run **Forge Agent: Open Chat** from the Command Palette.

## Chat and edits

The extension uses `@truefoundry/trueforge-sdk` sessions and streamed turn events. Stop asks TrueForge to cancel the active session; if connection fails, remaining client rendering is stopped as well. Conversation history is held in the TrueForge session for the current chat panel.

When the agent returns a proposal, the chat shows a **Review proposed edits** button. You can also run **Forge Agent: Review Edit Proposal** and paste proposal JSON. Each target file is checked against the supplied original content, shown in a native VS Code diff, and written only after you choose **Apply this file**. Proposals currently support modifications to existing workspace files; file creation and deletion are not supported. Multiple files are reviewed one at a time.

The extension does not implement an MCP server or configure one implicitly. The MCP server must be connected to the saved TrueForge agent. This keeps the expected Daksh contract intact while their server is developed independently.

## Checks

`npm run check` validates the extension JavaScript syntax. Run `npm install` and launch the extension host for a local integration check with TrueForge.
