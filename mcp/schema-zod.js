import { z } from 'zod';

/**
 * Convert the app's JSON-schema-style action parameters
 * (`src/voice/actionSchemas.js`) into a zod raw shape for the MCP SDK.
 * Covers the subset the schemas use: string/number/boolean/array/object,
 * enum, min/max, minLength/maxLength, min/maxItems, required,
 * additionalProperties.
 */

function convertNode(node) {
  if (!node || typeof node !== 'object') return z.any();
  switch (node.type) {
    case 'string': {
      let schema = node.enum ? z.enum(node.enum) : z.string();
      if (typeof node.maxLength === 'number')
        schema = schema.max(node.maxLength);
      if (typeof node.minLength === 'number')
        schema = schema.min(node.minLength);
      return schema;
    }
    case 'number':
    case 'integer': {
      let schema = node.type === 'integer' ? z.number().int() : z.number();
      if (typeof node.minimum === 'number') schema = schema.min(node.minimum);
      if (typeof node.maximum === 'number') schema = schema.max(node.maximum);
      return schema;
    }
    case 'boolean':
      return z.boolean();
    case 'array': {
      let schema = z.array(convertNode(node.items));
      if (typeof node.minItems === 'number') schema = schema.min(node.minItems);
      if (typeof node.maxItems === 'number') schema = schema.max(node.maxItems);
      return schema;
    }
    case 'object': {
      const shape = {};
      const required = new Set(
        Array.isArray(node.required) ? node.required : [],
      );
      for (const [key, child] of Object.entries(node.properties || {})) {
        const converted = convertNode(child);
        shape[key] = required.has(key) ? converted : converted.optional();
      }
      let schema = z.object(shape);
      if (node.additionalProperties === false) schema = schema.strict();
      return schema;
    }
    default:
      return z.any();
  }
}

/** Build the zod raw shape for one action's `parameters` schema. */
export function actionInputShape(parameters) {
  const converted = convertNode(parameters || { type: 'object' });
  if (!(converted instanceof z.ZodObject)) return { _any: z.any() };
  return converted.shape;
}
