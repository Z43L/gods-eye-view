// Connect to a remote (tunneled) God's Eye View bridge as an MCP client.
// Usage: GEV_MCP_URL=<tunnel url> GEV_MCP_TOKEN=<token> node mcp/connect-remote.mjs [tool] [json-args]
// With no tool arg: runs MCP handshake + tools/list + gev_app_status.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const baseUrl = process.env.GEV_MCP_URL;
const token = process.env.GEV_MCP_TOKEN;
if (!baseUrl || !token) {
  console.error('Set GEV_MCP_URL and GEV_MCP_TOKEN first.');
  process.exit(2);
}

const child = spawn('node', [path.join(here, 'server.mjs')], {
  env: { ...process.env, GEV_BASE_URL: baseUrl, GEV_AGENT_TOKEN: token },
  stdio: ['pipe', 'pipe', 'inherit'],
});

let id = 0;
const pending = new Map();
let buf = '';
child.stdout.on('data', (d) => {
  buf += d.toString();
  let nl;
  while ((nl = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve } = pending.get(msg.id);
      pending.delete(msg.id);
      resolve(msg);
    }
  }
});

function send(payload) {
  child.stdin.write(JSON.stringify(payload) + '\n');
}
function request(method, params) {
  const reqId = ++id;
  return new Promise((resolve) => {
    pending.set(reqId, { resolve });
    send({ jsonrpc: '2.0', id: reqId, method, params });
  });
}

await request('initialize', {
  protocolVersion: '2024-11-05',
  capabilities: {},
  clientInfo: { name: 'gev-remote-connect', version: '1.0.0' },
});
send({ jsonrpc: '2.0', method: 'notifications/initialized' });

const tool = process.argv[2];
if (!tool) {
  const list = await request('tools/list', {});
  const names = (list.result?.tools || []).map((t) => t.name);
  console.log(`tools: ${names.length} (${names.slice(0, 8).join(', ')}${names.length > 8 ? ', …' : ''})`);
  const status = await request('tools/call', { name: 'gev_app_status', arguments: {} });
  console.log('gev_app_status:', JSON.stringify(status.result ?? status.error, null, 2));
} else {
  const args = process.argv[3] ? JSON.parse(process.argv[3]) : {};
  const res = await request('tools/call', { name: tool, arguments: args });
  console.log(JSON.stringify(res.result ?? res.error, null, 2));
}
child.kill();
