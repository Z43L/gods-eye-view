import {
  createAgentBridgeQueue,
  admitAgentBridgeRequest,
  AGENT_TOKEN_HEADER,
} from '../../src/agent/bridgeQueue.mjs';
import { GEV_ACTION_SCHEMAS } from '../../src/voice/actionSchemas.js';

/**
 * Agent bridge — dev-server only.
 *
 * Lets an external agent (via the MCP server in `mcp/`) drive the running
 * browser app with the same action vocabulary as voice mode. The browser app
 * long-polls for commands; the MCP server enqueues them and waits for results.
 *
 *   POST /api/agent/command        { name, args } -> { id }
 *   GET  /api/agent/poll?waitMs=   -> next { id, name, args } or 204
 *   POST /api/agent/result         { id, ok, result?, error? } -> { ok: true }
 *   GET  /api/agent/result/:id?waitMs= -> outcome or 204
 *   POST /api/agent/heartbeat      { app? } -> { ok: true }
 *   GET  /api/agent/status         -> { connected, pendingCommands, app }
 *   POST /api/agent/reset         -> clears the queue
 *
 * Everything here is loopback-only by default: the bridge refuses proxied or
 * non-loopback traffic, because a queued command executes arbitrary app
 * actions. Set `GEV_AGENT_TOKEN` to allow remote access (tunnel, LAN):
 * requests carrying the token in the `x-gev-agent-token` header are admitted
 * from anywhere. The token is injected into the page as
 * `window.__GEV_AGENT_TOKEN` so the in-page channel keeps working when the
 * app itself is opened through the tunnel.
 */

/** Synthetic commands handled by the app-side channel itself. */
const SYNTHETIC_COMMANDS = new Set(['ping', 'capture_screenshot']);

const KNOWN_COMMAND_NAMES = new Set([
  ...GEV_ACTION_SCHEMAS.map((schema) => schema.name),
  ...SYNTHETIC_COMMANDS,
]);

const HEARTBEAT_TTL_MS = 45 * 1000;
const MAX_BODY_BYTES = 256 * 1024;

// Shared secret for remote access. Empty = loopback-only (default).
const AGENT_TOKEN = String(process.env.GEV_AGENT_TOKEN || '').trim();

function agentBridgeEndpoint() {
  const queue = createAgentBridgeQueue();
  let lastHeartbeatAt = 0;
  let appInfo = null;

  const respond = (res, statusCode, payload) => {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Frame-Options', 'DENY');
    res.end(JSON.stringify(payload));
  };

  const admit = (req, res) => {
    const verdict = admitAgentBridgeRequest({
      remoteAddress: req.socket?.remoteAddress,
      headers: req.headers,
      token: AGENT_TOKEN || undefined,
    });
    if (!verdict.ok) respond(res, verdict.status, { error: verdict.error });
    return verdict.ok;
  };

  const readJsonBody = (req) =>
    new Promise((resolve, reject) => {
      let body = '';
      let overflowed = false;
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_BYTES) {
          overflowed = true;
          req.destroy();
        }
      });
      req.on('end', () => {
        if (overflowed) return reject(new Error('Request too large'));
        try {
          resolve(JSON.parse(body || '{}'));
        } catch {
          reject(new Error('Invalid JSON'));
        }
      });
      req.on('error', reject);
    });

  const parseWaitMs = (url, fallback, cap) => {
    const raw = Number(url.searchParams.get('waitMs'));
    if (!Number.isFinite(raw) || raw < 0) return fallback;
    return Math.min(raw, cap);
  };

  return {
    name: 'gev-agent-bridge',
    // serve AND not preview: `vite preview` resolves with command 'serve' too,
    // so a bare apply:'serve' would still configure under preview. The
    // endpoints only install via configureServer (never configurePreviewServer).
    apply: (_config, { command, isPreview }) =>
      command === 'serve' && !isPreview,
    configureServer(server) {
      server.middlewares.use('/api/agent/command', async (req, res) => {
        if (req.method !== 'POST')
          return respond(res, 405, { error: 'Method not allowed' });
        if (!admit(req, res)) return;
        let payload;
        try {
          payload = await readJsonBody(req);
        } catch (error) {
          return respond(res, 400, { error: error.message });
        }
        const name = payload?.name;
        if (!KNOWN_COMMAND_NAMES.has(name))
          return respond(res, 400, { error: `Unknown command: ${name}` });
        const verdict = queue.enqueueCommand(name, payload?.args ?? {});
        if (!verdict.ok) return respond(res, 429, { error: verdict.error });
        respond(res, 200, { ok: true, id: verdict.id });
      });

      server.middlewares.use('/api/agent/poll', async (req, res) => {
        if (req.method !== 'GET')
          return respond(res, 405, { error: 'Method not allowed' });
        if (!admit(req, res)) return;
        const url = new URL(req.url, 'http://localhost');
        const command = await queue.takeNextCommand({
          waitMs: parseWaitMs(url, 25000, 60000),
        });
        if (!command) {
          res.statusCode = 204;
          return res.end();
        }
        lastHeartbeatAt = Date.now();
        respond(res, 200, command);
      });

      // NOTE: connect strips the mount prefix, so req.url here is only the
      // remainder: '/' for POSTs and '/<id>' for GETs.
      server.middlewares.use('/api/agent/result', async (req, res, next) => {
        const remainder = req.url.split('?')[0];
        if (req.method === 'POST' && (remainder === '/' || remainder === '')) {
          if (!admit(req, res)) return;
          let payload;
          try {
            payload = await readJsonBody(req);
          } catch (error) {
            return respond(res, 400, { error: error.message });
          }
          const stored = queue.completeCommand(payload?.id, {
            ok: payload?.ok === true,
            result: payload?.result,
            error: payload?.error,
          });
          if (!stored) return respond(res, 400, { error: 'Unknown result id' });
          return respond(res, 200, { ok: true });
        }
        const match = /^\/([^/?]+)$/.exec(remainder);
        if (req.method === 'GET' && match) {
          if (!admit(req, res)) return;
          const url = new URL(req.url, 'http://localhost');
          const outcome = await queue.takeResult(decodeURIComponent(match[1]), {
            waitMs: parseWaitMs(url, 120000, 300000),
          });
          if (!outcome) {
            res.statusCode = 204;
            return res.end();
          }
          return respond(res, 200, outcome);
        }
        return next();
      });

      server.middlewares.use('/api/agent/heartbeat', async (req, res) => {
        if (req.method !== 'POST')
          return respond(res, 405, { error: 'Method not allowed' });
        if (!admit(req, res)) return;
        let payload = {};
        try {
          payload = await readJsonBody(req);
        } catch {
          payload = {};
        }
        lastHeartbeatAt = Date.now();
        if (payload && typeof payload.app === 'object' && payload.app !== null)
          appInfo = payload.app;
        respond(res, 200, { ok: true });
      });

      server.middlewares.use('/api/agent/status', (req, res) => {
        if (req.method !== 'GET')
          return respond(res, 405, { error: 'Method not allowed' });
        if (!admit(req, res)) return;
        const msAgo =
          lastHeartbeatAt === 0 ? null : Date.now() - lastHeartbeatAt;
        respond(res, 200, {
          ok: true,
          connected: msAgo !== null && msAgo <= HEARTBEAT_TTL_MS,
          lastHeartbeatMsAgo: msAgo,
          app: appInfo,
          ...queue.stats(),
        });
      });

      server.middlewares.use('/api/agent/reset', (req, res) => {
        if (req.method !== 'POST')
          return respond(res, 405, { error: 'Method not allowed' });
        if (!admit(req, res)) return;
        queue.reset();
        respond(res, 200, { ok: true });
      });
    },

    // Expose the agent token to the page so the in-page channel can
    // authenticate when the app itself is opened through a tunnel/URL that
    // is not loopback. Anyone who can load the page already needs the
    // tunnel URL; the token stays a shared secret for that audience.
    transformIndexHtml(html) {
      if (!AGENT_TOKEN) return html;
      const snippet = `<script>window.__GEV_AGENT_TOKEN=${JSON.stringify(AGENT_TOKEN)};</script>`;
      return html.replace('</head>', `${snippet}</head>`);
    },
  };
}

export { agentBridgeEndpoint, KNOWN_COMMAND_NAMES };
