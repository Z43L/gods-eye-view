import { createGevActionRunner } from '../voice/gevActions.js';

/**
 * Agent channel — the app side of the MCP/agent bridge.
 *
 * Long-polls the dev server (`/api/agent/poll`) for commands queued by an
 * external agent (the MCP server in `mcp/`), executes them through the same
 * GEV action runner voice mode uses, and posts results back. This gives any
 * agent the full voice-mode vocabulary: navigation, layers, camera, scenes,
 * annotations, CCTV, radio, tracking, and analyst queries.
 *
 * Synthetic commands handled here (not part of the voice vocabulary):
 *   ping               -> { pong: true }
 *   capture_screenshot -> { mimeType, dataUrl } JPEG of the current globe view
 *
 * Enabled in dev builds by default; `?agent=0` disables it, `?agent=1` forces
 * it on in any build (the poll simply stops if the endpoints are absent).
 */

const POLL_WAIT_MS = 25000;
const HEARTBEAT_MS = 20000;
const RETRY_BACKOFF_MS = 3000;

// Injected by the dev server (agentBridge plugin) when GEV_AGENT_TOKEN is
// set, so the channel keeps working when the app is opened through a tunnel.
const AGENT_TOKEN_HEADER = 'x-gev-agent-token';
function bridgeHeaders() {
  const token =
    typeof window !== 'undefined' ? String(window.__GEV_AGENT_TOKEN || '') : '';
  return token !== '' ? { [AGENT_TOKEN_HEADER]: token } : {};
}

function bridgeEnabled() {
  try {
    const param = new URLSearchParams(window.location.search).get('agent');
    if (param === '0') return false;
    if (param === '1') return true;
  } catch {
    /* fall through to the build default */
  }
  return Boolean(import.meta.env.DEV);
}

function captureScreenshot(viewer) {
  if (!viewer?.scene || !viewer.canvas)
    throw new Error('Viewer is not ready for a screenshot');
  // Render synchronously first so toDataURL() in the same task sees a fresh
  // frame even without preserveDrawingBuffer.
  viewer.render();
  const dataUrl = viewer.canvas.toDataURL('image/jpeg', 0.82);
  if (typeof dataUrl !== 'string' || !dataUrl.startsWith('data:image/'))
    throw new Error('Screenshot capture failed');
  return { mimeType: 'image/jpeg', dataUrl };
}

async function postJson(url, payload, signal) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...bridgeHeaders() },
    body: JSON.stringify(payload),
    signal,
  });
  if (!response.ok)
    throw new Error(`Bridge request failed: ${response.status}`);
  return response.json();
}

/**
 * Attach the agent channel. Returns a handle with `stop()`; safe to call when
 * the bridge is disabled or unreachable (resolves to `{ active: false }`).
 */
export function initAgentChannel(options) {
  const {
    viewer,
    styleManager,
    dataManager,
    sceneDirector = null,
    annotations = null,
    placeSearch,
    floorServices,
    annotationResolver,
    searchNavigation,
    signal: externalSignal,
    appVersion = '0.1.1',
  } = options || {};

  const lifetime = new AbortController();
  if (externalSignal) {
    if (externalSignal.aborted) lifetime.abort();
    else
      externalSignal.addEventListener('abort', () => lifetime.abort(), {
        once: true,
      });
  }
  const signal = lifetime.signal;
  const stop = () => lifetime.abort();

  if (!bridgeEnabled()) return { active: false, stop };

  const runAction = createGevActionRunner({
    viewer,
    styleManager,
    dataManager,
    sceneDirector,
    annotations,
    placeSearch,
    floorServices,
    annotationResolver,
    searchNavigation,
  });

  const channel = {
    active: true,
    connected: false,
    stop,
  };

  const heartbeat = async () => {
    try {
      await postJson(
        '/api/agent/heartbeat',
        { app: { version: appVersion, href: window.location.href } },
        signal,
      );
      channel.connected = true;
    } catch {
      channel.connected = false;
    }
  };

  const executeCommand = async (command) => {
    const startedAt = Date.now();
    try {
      let result;
      if (command.name === 'ping') {
        result = { pong: true, at: new Date(startedAt).toISOString() };
      } else if (command.name === 'capture_screenshot') {
        result = captureScreenshot(viewer);
      } else {
        result = await runAction(command.name, command.args || {}, { signal });
      }
      return { ok: true, result };
    } catch (error) {
      if (signal.aborted) return null;
      return {
        ok: false,
        error: error?.message || String(error),
      };
    }
  };

  const pollOnce = async () => {
    const response = await fetch(`/api/agent/poll?waitMs=${POLL_WAIT_MS}`, {
      signal,
      headers: bridgeHeaders(),
    });
    if (response.status === 204) return null;
    if (response.status === 404) throw new Error('bridge-endpoints-missing');
    if (!response.ok) throw new Error(`Poll failed: ${response.status}`);
    return response.json();
  };

  const loop = async () => {
    // Fail fast when the bridge endpoints are absent (e.g. preview builds):
    // one status probe decides whether the loop is worthwhile.
    try {
      const status = await fetch('/api/agent/status', {
        signal,
        headers: bridgeHeaders(),
      });
      if (status.status === 404) return;
    } catch {
      return;
    }
    void heartbeat();
    const heartbeatTimer = setInterval(() => {
      if (!signal.aborted) void heartbeat();
    }, HEARTBEAT_MS);
    try {
      while (!signal.aborted) {
        let command = null;
        try {
          command = await pollOnce();
        } catch (error) {
          if (signal.aborted) break;
          if (error?.message === 'bridge-endpoints-missing') break;
          await new Promise((resolve) => setTimeout(resolve, RETRY_BACKOFF_MS));
          continue;
        }
        if (!command) continue;
        const outcome = await executeCommand(command);
        if (outcome === null) break; // aborted mid-command
        try {
          await postJson(
            '/api/agent/result',
            { id: command.id, ...outcome },
            signal,
          );
        } catch {
          /* result delivery failed; the waiter will time out honestly */
        }
      }
    } finally {
      clearInterval(heartbeatTimer);
    }
  };

  // Never let the bridge break app boot.
  loop().catch(() => {});
  window.__gevAgentChannel = channel;
  return channel;
}
