const vscode = require('vscode');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const { createTemporaryMcpBridge, registerTemporaryBridge } = require('./temp-mcp-bridge');
const SYSTEM_INSTRUCTIONS = `You are Forge Agent, a coding assistant working in the user's VS Code workspace. Use only MCP tools configured on your TrueForge agent for workspace inspection; do not claim to inspect files unless tools returned them. Never write files directly. When changes are needed, return a JSON proposal with shape {"proposalId":"unique-id","files":[{"path":"relative/path","operation":"modify","originalContent":"old","proposedContent":"new","reason":"why"}]}. Keep answers concise.`;
let temporaryBridge;
let bridgeToken;
let bridgeReady = Promise.resolve();
let bridgeSetupPromise;

function activate(context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('forgeAgent.openChat', () => openChat(context)),
    vscode.commands.registerCommand('forgeAgent.connectTemporaryMcpBridge', async () => {
      bridgeReady = connectTemporaryBridge(context);
      try { await bridgeReady; vscode.window.showInformationMessage('Temporary workspace tools are connected to the saved TrueForge agent.'); }
      catch (error) { vscode.window.showErrorMessage(`Temporary MCP bridge: ${error.message || error}`); }
    }),
    vscode.commands.registerCommand('forgeAgent.reviewProposal', async () => {
      const input = await vscode.window.showInputBox({ prompt: 'Paste the complete proposal JSON from Forge Agent', placeHolder: '{"proposalId":"...","files":[...]}' });
      if (input) await reviewProposal(input);
    })
  );
  context.subscriptions.push({ dispose: () => { if (temporaryBridge) temporaryBridge.close(); temporaryBridge = undefined; } });
  bridgeReady = connectTemporaryBridge(context);
  bridgeReady.catch(error => vscode.window.showWarningMessage(`Forge Agent workspace tools could not connect: ${error.message || error}. Run “Forge Agent: Connect Temporary MCP Bridge” to retry.`));
}

function connectTemporaryBridge(context) {
  if (!bridgeSetupPromise) bridgeSetupPromise = setupTemporaryBridge(context).finally(() => { bridgeSetupPromise = undefined; });
  return bridgeSetupPromise;
}

async function setupTemporaryBridge(context) {
  if (!vscode.workspace.workspaceFolders?.length) throw new Error('Open a workspace folder before connecting the temporary workspace tools.');
  if (!temporaryBridge) {
    bridgeToken = await context.secrets.get('forgeAgent.temporaryMcpBearerToken');
    if (!bridgeToken) {
      bridgeToken = crypto.randomBytes(32).toString('hex');
      await context.secrets.store('forgeAgent.temporaryMcpBearerToken', bridgeToken);
    }
    temporaryBridge = await createTemporaryMcpBridge({
      workspaceRoot: async () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath,
      token: bridgeToken,
      port: 0
    });
  }

  const cfg = vscode.workspace.getConfiguration('forgeAgent');
  const agentName = cfg.get('agentName');
  if (!agentName) throw new Error('Set forgeAgent.agentName to the saved TrueForge agent to update.');
  const options = { baseUrl: cfg.get('baseUrl'), timeoutInSeconds: 30 };
  const trueForgeToken = cfg.get('token'); if (trueForgeToken) options.token = trueForgeToken;
  const { TrueForge } = await import('@truefoundry/trueforge-sdk');
  const client = new TrueForge(options);

  try {
    await registerTemporaryBridge({ client, url: temporaryBridge.url, token: bridgeToken, agentName });
  } catch (error) {
    const details = error.body?.error?.message || error.message || '';
    if (/Outbound URL blocked/i.test(details)) throw new Error('TrueForge blocked the local MCP URL. Add 127.0.0.1 to OUTBOUND_URL_ALLOWED_HOSTS and restart TrueForge before retrying.');
    throw error;
  }
  return temporaryBridge.url;
}

function openChat(context) {
  const panel = vscode.window.createWebviewPanel('forgeAgent.chat', 'Forge Agent', vscode.ViewColumn.Beside, { enableScripts: true, retainContextWhenHidden: true });
  panel.webview.html = html(panel.webview);
  let clientPromise;
  let sessionId;
  let cancelRequested = false;
  let generation = 0;
  const getClient = async () => {
    if (!clientPromise) clientPromise = import('@truefoundry/trueforge-sdk').then(({ TrueForge }) => {
      const cfg = vscode.workspace.getConfiguration('forgeAgent');
      const opts = { baseUrl: cfg.get('baseUrl'), timeoutInSeconds: 600 };
      const token = cfg.get('token'); if (token) opts.token = token;
      return new TrueForge(opts);
    });
    return clientPromise;
  };
  panel.webview.onDidReceiveMessage(async msg => {
    if (msg.type === 'cancel') {
      cancelRequested = true; generation++;
      if (sessionId) getClient().then(c => c.sessions.cancel(sessionId)).catch(() => {});
      panel.webview.postMessage({ type: 'state', busy: false });
      return;
    }
    if (msg.type === 'proposal') { reviewProposal(msg.proposal); return; }
    if (msg.type !== 'send' || !String(msg.text || '').trim()) return;
    const current = ++generation; cancelRequested = false;
    let responseText = '';
    panel.webview.postMessage({ type: 'state', busy: true });
    try {
      await bridgeReady;
      const client = await getClient();
      if (!sessionId) {
        const cfg = vscode.workspace.getConfiguration('forgeAgent');
        const agentName = cfg.get('agentName');
        if (!agentName) throw new Error('Set forgeAgent.agentName to a saved TrueForge agent with the MCP workspace server configured.');
        const agent = { name: agentName };
        const result = await client.sessions.create({ agent });
        sessionId = result.data.id;
        if (current !== generation) return;
      }
      const stream = await client.sessions.createTurnStream(sessionId, { input: [{ type: 'user.message', content: `${SYSTEM_INSTRUCTIONS}\n\nUser request:\n${msg.text}` }] });
      for await (const event of stream) {
        if (current !== generation || cancelRequested) continue;
        if (event.type === 'model.message.delta' && event.content && event.threadId === 'main') { responseText += event.content; panel.webview.postMessage({ type: 'delta', text: event.content }); }
        if (event.type === 'turn.done' && event.state && event.state.status === 'error') throw new Error(event.state.message || 'TrueForge turn failed.');
      }
      if (current === generation) {
        panel.webview.postMessage({ type: 'done' });
        const proposal = extractProposal(responseText);
        if (proposal) panel.webview.postMessage({ type: 'proposalAvailable', proposal });
      }
    } catch (error) {
      if (current === generation) panel.webview.postMessage({ type: 'error', message: error.message || String(error) });
    } finally {
      if (current === generation) panel.webview.postMessage({ type: 'state', busy: false });
    }
  });
}

function extractProposal(text) {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  for (const candidate of [fenced && fenced[1], text.trim()]) {
    if (!candidate) continue;
    try { const value = JSON.parse(candidate); if (value && Array.isArray(value.files) && value.files.length) return value; } catch (_) {}
  }
  return undefined;
}

async function reviewProposal(proposal) {
  try {
    if (typeof proposal === 'string') proposal = JSON.parse(proposal);
    if (!proposal || !Array.isArray(proposal.files) || proposal.files.length < 1) throw new Error('Proposal must contain a non-empty files array.');
    const root = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
    if (!root) throw new Error('Open a workspace folder before reviewing edits.');
    for (const file of proposal.files) {
      if (!file || file.operation !== 'modify' || typeof file.path !== 'string' || typeof file.originalContent !== 'string' || typeof file.proposedContent !== 'string') throw new Error('Each file must be a modify operation with path, originalContent, and proposedContent strings.');
      const rel = file.path.replace(/\\/g, '/');
      if (!rel || path.posix.isAbsolute(rel) || rel.split('/').some(part => part === '..' || part === '.') || /^[a-zA-Z]:/.test(rel)) throw new Error(`Unsafe workspace path: ${file.path}`);
      const uri = vscode.Uri.joinPath(root.uri, ...rel.split('/'));
      const rootRealPath = await fs.realpath(root.uri.fsPath);
      const targetRealPath = await fs.realpath(uri.fsPath);
      const relativeRealPath = path.relative(rootRealPath, targetRealPath);
      if (relativeRealPath === '..' || relativeRealPath.startsWith(`..${path.sep}`) || path.isAbsolute(relativeRealPath)) throw new Error(`Path escapes workspace: ${file.path}`);
      let actual;
      try { actual = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString('utf8'); }
      catch (e) { if (e.code === 'FileNotFound') throw new Error(`File does not exist: ${file.path}`); throw e; }
      if (actual !== file.originalContent) throw new Error(`File changed since the proposal was created: ${file.path}. Ask the agent to reread it.`);
    }
    for (const [i, file] of proposal.files.entries()) {
      const rel = file.path.replace(/\\/g, '/');
      const target = vscode.Uri.joinPath(root.uri, ...rel.split('/'));
      const proposed = vscode.Uri.parse(`forge-proposal:${encodeURIComponent(rel)}?id=${encodeURIComponent(proposal.proposalId || 'proposal')}-${i}`);
      const original = vscode.Uri.parse(`forge-original:${encodeURIComponent(rel)}?id=${encodeURIComponent(proposal.proposalId || 'proposal')}-${i}`);
      providers.set(proposed.toString(), file.proposedContent);
      providers.set(original.toString(), file.originalContent);
      const title = `Forge proposal: ${rel}`;
      await vscode.commands.executeCommand('vscode.diff', original, proposed, title, { preview: false });
      const choice = await vscode.window.showInformationMessage(`${file.reason || 'Review proposed change'} — ${rel}`, 'Apply this file', 'Skip');
      if (choice === 'Apply this file') {
        const rootRealPath = await fs.realpath(root.uri.fsPath);
        const targetRealPath = await fs.realpath(target.fsPath);
        const relativeRealPath = path.relative(rootRealPath, targetRealPath);
        if (relativeRealPath === '..' || relativeRealPath.startsWith(`..${path.sep}`) || path.isAbsolute(relativeRealPath)) { vscode.window.showErrorMessage(`${rel} no longer resolves inside the workspace; proposal was not applied.`); continue; }
        const now = Buffer.from(await vscode.workspace.fs.readFile(target)).toString('utf8');
        if (now !== file.originalContent) { vscode.window.showErrorMessage(`${rel} changed during review; proposal was not applied.`); continue; }
        await vscode.workspace.fs.writeFile(target, Buffer.from(file.proposedContent, 'utf8'));
        vscode.window.showInformationMessage(`Applied Forge proposal to ${rel}.`);
      }
    }
  } catch (error) { vscode.window.showErrorMessage(`Forge proposal rejected: ${error.message || error}`); }
}

const providers = new Map();
function html(webview) {
  if (!providerRegistered) { providerRegistered = true; vscode.workspace.registerTextDocumentContentProvider('forge-proposal', { provideTextDocumentContent: uri => providers.get(uri.toString()) || '' }); vscode.workspace.registerTextDocumentContentProvider('forge-original', { provideTextDocumentContent: uri => providers.get(uri.toString()) || '' }); }
  const nonce = String(Date.now());
  return `<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'"><style>
  body{font:var(--vscode-font);color:var(--vscode-foreground);padding:0 18px;display:flex;flex-direction:column;height:95vh}h2{font-size:1.1em}.messages{flex:1;overflow:auto}.msg{white-space:pre-wrap;padding:10px 12px;margin:8px 0;border-radius:6px;background:var(--vscode-editor-inactiveSelectionBackground)}.user{background:var(--vscode-input-background)}.error{color:var(--vscode-errorForeground)}form{display:flex;gap:8px;padding:12px 0}textarea{flex:1;resize:vertical;min-height:56px;color:var(--vscode-input-foreground);background:var(--vscode-input-background);border:1px solid var(--vscode-input-border);padding:8px}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;padding:8px 12px;cursor:pointer}button:disabled{opacity:.5}#status{min-height:1.2em;color:var(--vscode-descriptionForeground)}</style></head><body><h2>Forge Agent</h2><div id="messages" class="messages"></div><div id="status"></div><button id="review" type="button" hidden>Review proposed edits</button><form><textarea id="prompt" placeholder="Ask Forge Agent…" aria-label="Message"></textarea><button id="send">Send</button><button type="button" id="stop" disabled>Stop</button></form><script nonce="${nonce}">
  const vscode=acquireVsCodeApi(), box=document.getElementById('messages'), input=document.getElementById('prompt'), send=document.getElementById('send'), stop=document.getElementById('stop'), review=document.getElementById('review'), status=document.getElementById('status');let active=null,proposal=null;
  function add(text,cls){const el=document.createElement('div');el.className='msg '+cls;el.textContent=text;box.appendChild(el);box.scrollTop=box.scrollHeight;return el}
  document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();const text=input.value.trim();if(!text)return;proposal=null;review.hidden=true;add(text,'user');active=add('','assistant');vscode.postMessage({type:'send',text});input.value='';});
  stop.onclick=()=>vscode.postMessage({type:'cancel'});
  review.onclick=()=>proposal&&vscode.postMessage({type:'proposal',proposal});
  window.addEventListener('message',e=>{const m=e.data;if(m.type==='delta'&&active){active.textContent+=m.text;box.scrollTop=box.scrollHeight;}if(m.type==='done')active=null;if(m.type==='proposalAvailable'){proposal=m.proposal;review.hidden=false;}if(m.type==='error'){add(m.message,'error');active=null;}if(m.type==='state'){send.disabled=m.busy;stop.disabled=!m.busy;status.textContent=m.busy?'Working…':'';}});
  input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send.click();}});
  </script></body></html>`;
}
let providerRegistered = false;
function deactivate() {}
module.exports = { activate, deactivate };
