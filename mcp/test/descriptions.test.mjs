import test from 'node:test';
import assert from 'node:assert/strict';
import { GEV_ACTION_SCHEMAS } from '../../src/voice/actionSchemas.js';
import { ACTION_DESCRIPTIONS, UTILITY_DESCRIPTIONS } from '../descriptions.js';

test('every voice action has an agent-facing description', () => {
  const missing = GEV_ACTION_SCHEMAS.filter(
    (schema) =>
      typeof ACTION_DESCRIPTIONS[schema.name] !== 'string' ||
      ACTION_DESCRIPTIONS[schema.name].length < 20,
  ).map((schema) => schema.name);
  assert.deepEqual(missing, []);
});

test('no description is orphaned', () => {
  const known = new Set(GEV_ACTION_SCHEMAS.map((schema) => schema.name));
  const orphaned = Object.keys(ACTION_DESCRIPTIONS).filter(
    (name) => !known.has(name),
  );
  assert.deepEqual(orphaned, []);
});

test('utility descriptions are present', () => {
  for (const key of ['gev_app_status', 'gev_wait_for_app', 'gev_capture_screenshot']) {
    assert.ok(
      typeof UTILITY_DESCRIPTIONS[key] === 'string' &&
        UTILITY_DESCRIPTIONS[key].length > 10,
      key,
    );
  }
});
