import test from 'node:test';
import assert from 'node:assert/strict';
import { createBridgeClient } from '../bridge.js';

/** Minimal in-memory stand-in for the dev server's /api/agent/* surface. */
function stubServer() {
  const commands = new Map();
  let seq = 0;
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url, method: options.method });
    const { pathname, searchParams } = new URL(url);
    const json = (status, payload) => ({
      status,
      ok: status >= 200 && status < 300,
      json: async () => payload,
    });
    if (pathname === '/api/agent/status')
      return json(200, { ok: true, connected: true, pendingCommands: 0 });
    if (pathname === '/api/agent/command' && options.method === 'POST') {
      const id = `cmd-${++seq}`;
      commands.set(id, JSON.parse(options.body));
      return json(200, { ok: true, id });
    }
    const resultMatch = /^\/api\/agent\/result\/(.+)$/.exec(pathname);
    if (resultMatch && options.method === 'GET') {
      const id = decodeURIComponent(resultMatch[1]);
      const command = commands.get(id);
      if (!command) return json(200, null);
      // The stub "app" answers zoom_to_globe and fails everything else.
      if (command.name === 'zoom_to_globe')
        return json(200, { id, ok: true, result: { zoomed: true } });
      return json(200, { id, ok: false, error: 'simulated app failure' });
    }
    return json(404, { error: 'not found' });
  };
  return { fetchImpl, calls };
}

test('call() enqueues and returns the app result', async () => {
  const { fetchImpl, calls } = stubServer();
  const bridge = createBridgeClient({ baseUrl: 'http://x', fetchImpl });
  const result = await bridge.call('zoom_to_globe', {});
  assert.deepEqual(result, { zoomed: true });
  assert.ok(calls.some((c) => c.url.includes('/api/agent/command')));
  assert.ok(calls.some((c) => c.url.includes('/api/agent/result/cmd-1')));
});

test('call() surfaces app failures as errors', async () => {
  const { fetchImpl } = stubServer();
  const bridge = createBridgeClient({ baseUrl: 'http://x', fetchImpl });
  await assert.rejects(
    () => bridge.call('fly_to_location', { query: 'Madrid' }),
    /simulated app failure/,
  );
});

test('call() reports unreachable dev servers helpfully', async () => {
  const bridge = createBridgeClient({
    baseUrl: 'http://127.0.0.1:9',
    fetchImpl: async () => {
      throw new Error('ECONNREFUSED');
    },
  });
  await assert.rejects(() => bridge.status(), /npm run dev/);
});

test('waitForApp resolves once the app connects', async () => {
  let connected = false;
  const bridge = createBridgeClient({
    baseUrl: 'http://x',
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      json: async () => ({ ok: true, connected }),
    }),
  });
  setTimeout(() => {
    connected = true;
  }, 30);
  const status = await bridge.waitForApp({ timeoutMs: 2000, intervalMs: 10 });
  assert.equal(status.connected, true);
});

test('waitForApp times out with guidance', async () => {
  const bridge = createBridgeClient({
    baseUrl: 'http://x',
    fetchImpl: async () => ({
      status: 200,
      ok: true,
      json: async () => ({ ok: true, connected: false }),
    }),
  });
  await assert.rejects(
    () => bridge.waitForApp({ timeoutMs: 50, intervalMs: 10 }),
    /did not connect/,
  );
});
