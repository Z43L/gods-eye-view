import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { GEV_ACTION_SCHEMAS } from '../../src/voice/actionSchemas.js';
import { actionInputShape } from '../schema-zod.js';

test('every action schema converts to a zod object shape', () => {
  assert.ok(GEV_ACTION_SCHEMAS.length > 20);
  for (const schema of GEV_ACTION_SCHEMAS) {
    const shape = actionInputShape(schema.parameters);
    const parsed = z.object(shape);
    assert.ok(
      parsed instanceof z.ZodObject,
      `schema did not convert: ${schema.name}`,
    );
  }
});

test('required fields stay required, optional stay optional', () => {
  const shape = actionInputShape(
    GEV_ACTION_SCHEMAS.find((s) => s.name === 'set_layer_visibility')
      .parameters,
  );
  const parsed = z.object(shape);
  assert.doesNotThrow(() =>
    parsed.parse({ layerId: 'flights', enabled: true }),
  );
  assert.throws(() => parsed.parse({ enabled: true }));
  assert.throws(() => parsed.parse({ layerId: 'flights' }));
});

test('enums reject unknown values', () => {
  const shape = actionInputShape(
    GEV_ACTION_SCHEMAS.find((s) => s.name === 'set_layer_visibility')
      .parameters,
  );
  assert.throws(() =>
    z.object(shape).parse({ layerId: 'nope', enabled: true }),
  );
});

test('numeric bounds are enforced', () => {
  const shape = actionInputShape(
    GEV_ACTION_SCHEMAS.find((s) => s.name === 'fly_to_location').parameters,
  );
  const parsed = z.object(shape);
  assert.doesNotThrow(() => parsed.parse({ latitude: 40.4, longitude: -3.7 }));
  assert.throws(() => parsed.parse({ latitude: 91 }));
  assert.throws(() => parsed.parse({ longitude: -181 }));
});

test('nested objects and arrays convert (annotate_map, analyst_query)', () => {
  const annotate = actionInputShape(
    GEV_ACTION_SCHEMAS.find((s) => s.name === 'annotate_map').parameters,
  );
  assert.doesNotThrow(() =>
    z
      .object(annotate)
      .parse({ annotations: [{ type: 'pin', latitude: 40, longitude: -3 }] }),
  );
  assert.throws(() => z.object(annotate).parse({ annotations: [] }));
  assert.throws(() =>
    z.object(annotate).parse({ annotations: [{ type: 'nope' }] }),
  );

  const analyst = actionInputShape(
    GEV_ACTION_SCHEMAS.find((s) => s.name === 'analyst_query').parameters,
  );
  assert.doesNotThrow(() =>
    z.object(analyst).parse({
      layers: ['flights'],
      filters: [{ field: 'alt', op: 'gt', value: 10000 }],
      scope: { kind: 'view' },
    }),
  );
});

test('unknown keys are stripped, never forwarded', () => {
  const shape = actionInputShape(
    GEV_ACTION_SCHEMAS.find((s) => s.name === 'zoom_to_globe').parameters,
  );
  // zod strips unknown keys by default; the app runner only reads known
  // fields, so extras can never leak into an action.
  assert.deepEqual(z.object(shape).parse({ surprise: 1 }), {});
});
