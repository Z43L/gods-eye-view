/**
 * Pure in-memory command queue for the agent bridge.
 *
 * The dev server holds one of these; the MCP server POSTs commands into it and
 * the browser app long-polls for work. Nothing here touches the network, the
 * DOM, or Vite, so it stays unit-testable in plain Node.
 */

const DEFAULT_MAX_PENDING = 64;
const DEFAULT_COMMAND_TTL_MS = 5 * 60 * 1000;
const DEFAULT_RESULT_TTL_MS = 10 * 60 * 1000;

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

/** Validate the shape of an inbound command before it enters the queue. */
export function validateCommandShape(command) {
  if (!isPlainObject(command))
    return { ok: false, error: 'Command must be a JSON object' };
  const { name, args } = command;
  if (typeof name !== 'string' || name.trim() === '')
    return { ok: false, error: 'Command "name" must be a non-empty string' };
  if (name.length > 120)
    return { ok: false, error: 'Command "name" is too long' };
  if (args !== undefined && !isPlainObject(args))
    return { ok: false, error: 'Command "args" must be a JSON object' };
  return { ok: true };
}

/**
 * Create the queue. `now` and `createId` are injectable for tests.
 *
 * A command is `{ id, name, args, enqueuedAt }`. Results are keyed by command
 * id as `{ id, ok, result?, error?, completedAt }` and expire after
 * `resultTtlMs`. Pending commands expire after `commandTtlMs` so a stale
 * command from a dead client can never fire minutes later.
 */
export function createAgentBridgeQueue({
  now = () => Date.now(),
  createId = () =>
    `${now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
  maxPending = DEFAULT_MAX_PENDING,
  commandTtlMs = DEFAULT_COMMAND_TTL_MS,
  resultTtlMs = DEFAULT_RESULT_TTL_MS,
} = {}) {
  const pending = [];
  const results = new Map();
  const commandWaiters = [];
  const resultWaiters = new Map();

  const prunePending = () => {
    const cutoff = now() - commandTtlMs;
    let removed = 0;
    for (let i = pending.length - 1; i >= 0; i--) {
      if (pending[i].enqueuedAt <= cutoff) {
        pending.splice(i, 1);
        removed++;
      }
    }
    return removed;
  };

  const pruneResults = () => {
    const cutoff = now() - resultTtlMs;
    for (const [id, outcome] of results) {
      if (outcome.completedAt <= cutoff) {
        results.delete(id);
        resultWaiters.delete(id);
      }
    }
  };

  const wakeCommandWaiters = () => {
    while (commandWaiters.length > 0 && pending.length > 0) {
      const waiter = commandWaiters.shift();
      clearTimeout(waiter.timer);
      waiter.resolve(pending.shift());
    }
  };

  return {
    enqueueCommand(name, args = {}) {
      prunePending();
      const shape = validateCommandShape({ name, args });
      if (!shape.ok) return { ok: false, error: shape.error };
      if (pending.length >= maxPending)
        return { ok: false, error: 'Command queue is full' };
      const command = {
        id: createId(),
        name,
        args,
        enqueuedAt: now(),
      };
      pending.push(command);
      wakeCommandWaiters();
      return { ok: true, id: command.id };
    },

    /** Take the next command, optionally waiting up to `waitMs` for one. */
    takeNextCommand({ waitMs = 0 } = {}) {
      prunePending();
      if (pending.length > 0) return Promise.resolve(pending.shift());
      const wait = Math.max(0, Number(waitMs) || 0);
      if (wait === 0) return Promise.resolve(null);
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          const index = commandWaiters.findIndex((w) => w.timer === timer);
          if (index >= 0) commandWaiters.splice(index, 1);
          resolve(null);
        }, wait);
        commandWaiters.push({ timer, resolve });
      });
    },

    pendingCount() {
      prunePending();
      return pending.length;
    },

    completeCommand(id, outcome) {
      if (typeof id !== 'string' || id === '') return false;
      const record = {
        id,
        ok: outcome?.ok === true,
        completedAt: now(),
      };
      if (outcome && 'result' in outcome) record.result = outcome.result;
      if (outcome && 'error' in outcome)
        record.error = String(outcome.error ?? '');
      results.set(id, record);
      pruneResults();
      const waiters = resultWaiters.get(id);
      if (waiters) {
        resultWaiters.delete(id);
        for (const waiter of waiters) {
          clearTimeout(waiter.timer);
          waiter.resolve(record);
        }
      }
      return true;
    },

    /** Fetch a result, optionally waiting up to `waitMs` for completion. */
    takeResult(id, { waitMs = 0 } = {}) {
      pruneResults();
      if (typeof id !== 'string' || id === '')
        return Promise.resolve({ ok: false, error: 'Unknown result id' });
      const existing = results.get(id);
      if (existing) return Promise.resolve(existing);
      const wait = Math.max(0, Number(waitMs) || 0);
      if (wait === 0) return Promise.resolve(null);
      return new Promise((resolve) => {
        const timer = setTimeout(() => {
          const list = resultWaiters.get(id) || [];
          const index = list.findIndex((w) => w.timer === timer);
          if (index >= 0) list.splice(index, 1);
          if (list.length === 0) resultWaiters.delete(id);
          resolve(null);
        }, wait);
        const list = resultWaiters.get(id) || [];
        list.push({ timer, resolve });
        resultWaiters.set(id, list);
      });
    },

    reset() {
      pending.length = 0;
      results.clear();
      for (const waiter of commandWaiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.resolve(null);
      }
      for (const list of resultWaiters.values()) {
        for (const waiter of list) {
          clearTimeout(waiter.timer);
          waiter.resolve(null);
        }
      }
      resultWaiters.clear();
    },

    stats() {
      prunePending();
      pruneResults();
      return { pendingCommands: pending.length, storedResults: results.size };
    },
  };
}

export const AGENT_BRIDGE_LIMITS = Object.freeze({
  maxPending: DEFAULT_MAX_PENDING,
  commandTtlMs: DEFAULT_COMMAND_TTL_MS,
  resultTtlMs: DEFAULT_RESULT_TTL_MS,
});

const LOOPBACK_ADDRESSES = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

const PROXY_SIGNALS = [
  'forwarded',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-forwarded-proto',
  'x-real-ip',
  'cf-connecting-ip',
  'cf-ray',
];

/**
 * Pure admission gate for the bridge HTTP surface.
 *
 * Default: loopback socket only, never behind a reverse proxy. A queued
 * command executes arbitrary app actions, so the bridge must not answer LAN
 * or tunnel traffic uninvited.
 *
 * Remote use: when the dev server is started with `GEV_AGENT_TOKEN` set, a
 * request carrying the same token in the `x-gev-agent-token` header is
 * admitted from anywhere (tunnel, LAN). The token is the whole protection
 * there, so it must be long and random.
 */
export const AGENT_TOKEN_HEADER = 'x-gev-agent-token';

function tokensEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function admitAgentBridgeRequest({
  remoteAddress,
  headers = {},
  token,
} = {}) {
  const configured = String(token || '').trim();
  const presented = String(headers[AGENT_TOKEN_HEADER] || '').trim();
  if (
    configured !== '' &&
    presented !== '' &&
    tokensEqual(configured, presented)
  )
    return { ok: true };
  for (const name of PROXY_SIGNALS) {
    if (String(headers[name] || '').trim() !== '')
      return {
        ok: false,
        status: 403,
        error: 'Agent bridge refuses proxied requests',
      };
  }
  const address = String(remoteAddress || '').trim();
  if (!LOOPBACK_ADDRESSES.has(address))
    return { ok: false, status: 403, error: 'Agent bridge is loopback-only' };
  return { ok: true };
}
