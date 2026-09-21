/**
 * HTTP client for the God's Eye View agent bridge (`/api/agent/*` on the dev
 * server). Used by the MCP server; kept dependency-free so it is unit-testable.
 */

export const DEFAULT_BASE_URL = 'http://localhost:4173';
export const DEFAULT_COMMAND_TIMEOUT_MS = 120000;

export function bridgeError(message, hint) {
  const error = new Error(hint ? `${message} — ${hint}` : message);
  error.code = 'GEV_BRIDGE_ERROR';
  return error;
}

export function createBridgeClient({
  baseUrl = DEFAULT_BASE_URL,
  fetchImpl = fetch,
  commandTimeoutMs = DEFAULT_COMMAND_TIMEOUT_MS,
} = {}) {
  const base = String(baseUrl).replace(/\/+$/, '');

  const requestJson = async (method, path, body, { timeoutMs } = {}) => {
    let response;
    try {
      response = await fetchImpl(`${base}${path}`, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined,
      });
    } catch (error) {
      throw bridgeError(
        `Cannot reach the God's Eye View dev server at ${base}`,
        'run `npm run dev` in the repo and open the app in a browser',
      );
    }
    if (response.status === 204) return null;
    if (!response.ok) {
      let detail = '';
      try {
        detail = (await response.json())?.error || '';
      } catch {
        /* ignore */
      }
      throw bridgeError(
        `Bridge request failed (${response.status})`,
        detail || undefined,
      );
    }
    return response.json();
  };

  return {
    baseUrl: base,

    status() {
      return requestJson('GET', '/api/agent/status');
    },

    async waitForApp({ timeoutMs = 60000, intervalMs = 1500 } = {}) {
      const deadline = Date.now() + timeoutMs;
      let last = null;
      while (Date.now() < deadline) {
        try {
          last = await this.status();
          if (last?.connected) return last;
        } catch {
          /* dev server may not be up yet */
        }
        await new Promise((resolve) => setTimeout(resolve, intervalMs));
      }
      throw bridgeError(
        'The app did not connect to the agent bridge in time',
        'run `npm run dev` and open the app (the bridge activates automatically in dev)',
      );
    },

    /**
     * Enqueue a command and wait for the app to execute it. Resolves with the
     * action's result payload; rejects when the app reports failure.
     */
    async call(name, args = {}, { timeoutMs = commandTimeoutMs } = {}) {
      const queued = await requestJson('POST', '/api/agent/command', {
        name,
        args,
      });
      if (!queued?.id)
        throw bridgeError('The bridge did not accept the command');
      const outcome = await requestJson(
        'GET',
        `/api/agent/result/${encodeURIComponent(queued.id)}?waitMs=${Math.min(timeoutMs, 300000)}`,
        undefined,
        { timeoutMs: timeoutMs + 15000 },
      );
      if (!outcome)
        throw bridgeError(
          `Timed out waiting for the app to run "${name}"`,
          'the app may be busy or its tab suspended',
        );
      if (!outcome.ok)
        throw bridgeError(
          `The app failed to run "${name}"`,
          outcome.error || undefined,
        );
      return outcome.result;
    },

    reset() {
      return requestJson('POST', '/api/agent/reset', {});
    },
  };
}
