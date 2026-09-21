import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createAgentBridgeQueue,
  validateCommandShape,
  admitAgentBridgeRequest,
} from './bridgeQueue.mjs';

function controllableQueue(overrides = {}) {
  let t = 1000;
  let seq = 0;
  return {
    queue: createAgentBridgeQueue({
      now: () => t,
      createId: () => `cmd-${++seq}`,
      ...overrides,
    }),
    advance: (ms) => {
      t += ms;
    },
  };
}

test('enqueue/take round-trips a command', async () => {
  const { queue } = controllableQueue();
  const enqueued = queue.enqueueCommand('fly_to_location', { query: 'Madrid' });
  assert.equal(enqueued.ok, true);
  assert.equal(enqueued.id, 'cmd-1');
  assert.equal(queue.pendingCount(), 1);
  const taken = await queue.takeNextCommand();
  assert.equal(taken.id, 'cmd-1');
  assert.equal(taken.name, 'fly_to_location');
  assert.deepEqual(taken.args, { query: 'Madrid' });
  assert.equal(queue.pendingCount(), 0);
});

test('takeNextCommand waits for a later enqueue', async () => {
  const { queue } = controllableQueue();
  const pending = queue.takeNextCommand({ waitMs: 5000 });
  queue.enqueueCommand('ping', {});
  const taken = await pending;
  assert.equal(taken?.name, 'ping');
});

test('takeNextCommand resolves null when the wait expires', async () => {
  const { queue } = controllableQueue();
  const taken = await queue.takeNextCommand({ waitMs: 20 });
  assert.equal(taken, null);
});

test('complete/take result round-trip, waiting included', async () => {
  const { queue } = controllableQueue();
  const waiting = queue.takeResult('cmd-9', { waitMs: 5000 });
  assert.equal(
    queue.completeCommand('cmd-9', { ok: true, result: { n: 1 } }),
    true,
  );
  const outcome = await waiting;
  assert.equal(outcome.ok, true);
  assert.deepEqual(outcome.result, { n: 1 });
  // A second read still finds the stored outcome.
  const again = await queue.takeResult('cmd-9');
  assert.equal(again.ok, true);
});

test('failed outcomes carry the error text', async () => {
  const { queue } = controllableQueue();
  queue.completeCommand('cmd-2', { ok: false, error: 'boom' });
  const outcome = await queue.takeResult('cmd-2');
  assert.equal(outcome.ok, false);
  assert.equal(outcome.error, 'boom');
});

test('stale pending commands expire instead of firing late', async () => {
  const { queue, advance } = controllableQueue({ commandTtlMs: 1000 });
  queue.enqueueCommand('ping', {});
  advance(1500);
  assert.equal(queue.pendingCount(), 0);
  assert.equal(await queue.takeNextCommand(), null);
});

test('stored results expire', async () => {
  const { queue, advance } = controllableQueue({ resultTtlMs: 1000 });
  queue.completeCommand('cmd-3', { ok: true });
  advance(1500);
  assert.equal(await queue.takeResult('cmd-3'), null);
});

test('full queue rejects new commands', () => {
  const { queue } = controllableQueue({ maxPending: 2 });
  assert.equal(queue.enqueueCommand('a', {}).ok, true);
  assert.equal(queue.enqueueCommand('b', {}).ok, true);
  const verdict = queue.enqueueCommand('c', {});
  assert.equal(verdict.ok, false);
  assert.match(verdict.error, /full/);
});

test('reset clears pending commands, results and waiters', async () => {
  const { queue } = controllableQueue();
  // A blocked waiter wakes with null on reset.
  const waitingCommand = queue.takeNextCommand({ waitMs: 5000 });
  const waitingResult = queue.takeResult('cmd-1', { waitMs: 5000 });
  queue.reset();
  assert.equal(await waitingCommand, null);
  assert.equal(await waitingResult, null);
  // Queued-but-unconsumed commands are dropped too.
  queue.enqueueCommand('ping', {});
  queue.reset();
  assert.equal(queue.pendingCount(), 0);
  assert.equal(await queue.takeNextCommand(), null);
  assert.deepEqual(queue.stats(), { pendingCommands: 0, storedResults: 0 });
});

test('validateCommandShape rejects malformed commands', () => {
  assert.equal(validateCommandShape(null).ok, false);
  assert.equal(validateCommandShape({}).ok, false);
  assert.equal(validateCommandShape({ name: '' }).ok, false);
  assert.equal(validateCommandShape({ name: 'ping', args: 'nope' }).ok, false);
  assert.equal(validateCommandShape({ name: 'ping' }).ok, true);
});

test('admission allows loopback only and refuses proxies', () => {
  assert.equal(
    admitAgentBridgeRequest({ remoteAddress: '127.0.0.1' }).ok,
    true,
  );
  assert.equal(admitAgentBridgeRequest({ remoteAddress: '::1' }).ok, true);
  assert.equal(
    admitAgentBridgeRequest({ remoteAddress: '::ffff:127.0.0.1' }).ok,
    true,
  );
  const lan = admitAgentBridgeRequest({ remoteAddress: '192.168.1.10' });
  assert.equal(lan.ok, false);
  assert.equal(lan.status, 403);
  const proxied = admitAgentBridgeRequest({
    remoteAddress: '127.0.0.1',
    headers: { 'x-forwarded-for': '1.2.3.4' },
  });
  assert.equal(proxied.ok, false);
  assert.equal(proxied.status, 403);
  assert.equal(admitAgentBridgeRequest({}).ok, false);
});

test('admission accepts the agent token from anywhere, rejects wrong tokens', () => {
  const token = 's3cr3t-token';
  // Remote address + proxy headers are fine when the token matches.
  assert.equal(
    admitAgentBridgeRequest({
      remoteAddress: '203.0.113.7',
      headers: {
        'x-gev-agent-token': token,
        'x-forwarded-for': '203.0.113.7',
        'cf-ray': 'abc',
      },
      token,
    }).ok,
    true,
  );
  // Wrong token falls back to loopback rules: remote refused…
  assert.equal(
    admitAgentBridgeRequest({
      remoteAddress: '203.0.113.7',
      headers: { 'x-gev-agent-token': 'wrong' },
      token,
    }).ok,
    false,
  );
  // …but loopback still works without any token.
  assert.equal(
    admitAgentBridgeRequest({ remoteAddress: '127.0.0.1', token }).ok,
    true,
  );
  // No configured token: a presented token buys nothing.
  assert.equal(
    admitAgentBridgeRequest({
      remoteAddress: '203.0.113.7',
      headers: { 'x-gev-agent-token': 'anything' },
    }).ok,
    false,
  );
});
