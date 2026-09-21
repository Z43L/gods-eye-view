#!/usr/bin/env node
/**
 * God's Eye View MCP server — drive the whole app from any agent, like voice
 * mode but over MCP.
 *
 * Every voice-mode action (`src/voice/actionSchemas.js`) becomes a `gev_*`
 * tool; the tool call is forwarded through the dev server's agent bridge
 * (`/api/agent/*`, see `server/standalone/agentBridge.js`) to the running
 * browser app, which executes it and returns the result.
 *
 * Setup:
 *   1. `npm run dev` in the repo (the agent bridge activates automatically)
 *   2. Open the app in a browser (the app polls the bridge for commands)
 *   3. Point your MCP client at this server (stdio):
 *        { "command": "node", "args": ["/path/to/gods-eye-view/mcp/server.mjs"] }
 *
 * Env:
 *   GEV_BASE_URL           dev server URL (default http://localhost:4173)
 *   GEV_COMMAND_TIMEOUT_MS per-tool timeout waiting for the app (default 120000)
 *   GEV_AGENT_TOKEN        bridge token for remote access (must match the dev
 *                          server's; see `npm run dev:tunnel`)
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { GEV_ACTION_SCHEMAS } from '../src/voice/actionSchemas.js';
import { actionInputShape } from './schema-zod.js';
import { createBridgeClient } from './bridge.js';
import { ACTION_DESCRIPTIONS, UTILITY_DESCRIPTIONS } from './descriptions.js';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));

const baseUrl = process.env.GEV_BASE_URL || 'http://localhost:4173';
const commandTimeoutMs = Number(process.env.GEV_COMMAND_TIMEOUT_MS) || 120000;
const bridge = createBridgeClient({ baseUrl, commandTimeoutMs });

const server = new McpServer(
  { name: 'gods-eye-view', version: pkg.version },
  { capabilities: { tools: {} } },
);

const READ_ONLY_ACTIONS = new Set([
  'get_entity_context',
  'get_current_view_state',
  'analyst_query',
  'next_iss_pass',
  'control_scene', // list/status read; play/stop mutate but are idempotent-ish
]);

function toolError(message) {
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
  };
}

function toolJson(payload) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2),
      },
    ],
  };
}

function registerActionTool(schema) {
  const description =
    ACTION_DESCRIPTIONS[schema.name] || `Run the app action "${schema.name}".`;
  server.registerTool(
    `gev_${schema.name}`,
    {
      description,
      inputSchema: actionInputShape(schema.parameters),
      annotations: {
        readOnlyHint: READ_ONLY_ACTIONS.has(schema.name),
        destructiveHint: schema.name === 'clear_annotations',
        idempotentHint: schema.name.startsWith('get_'),
        openWorldHint: true, // actions reach live data feeds through the app
      },
    },
    async (args) => {
      try {
        const result = await bridge.call(schema.name, args ?? {});
        return toolJson({ ok: true, action: schema.name, result });
      } catch (error) {
        return toolError(error?.message || String(error));
      }
    },
  );
}

for (const schema of GEV_ACTION_SCHEMAS) registerActionTool(schema);

// --- Utility tools ---------------------------------------------------------

server.registerTool(
  'gev_app_status',
  {
    description: UTILITY_DESCRIPTIONS.gev_app_status,
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => {
    try {
      return toolJson(await bridge.status());
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

server.registerTool(
  'gev_wait_for_app',
  {
    description: UTILITY_DESCRIPTIONS.gev_wait_for_app,
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => {
    try {
      const status = await bridge.waitForApp({ timeoutMs: 90000 });
      return toolJson({ ok: true, ...status });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

server.registerTool(
  'gev_capture_screenshot',
  {
    description: UTILITY_DESCRIPTIONS.gev_capture_screenshot,
    inputSchema: {},
    annotations: { readOnlyHint: true },
  },
  async () => {
    try {
      const shot = await bridge.call('capture_screenshot', {});
      const dataUrl = shot?.dataUrl || '';
      const base64 = dataUrl.includes(',')
        ? dataUrl.slice(dataUrl.indexOf(',') + 1)
        : dataUrl;
      if (!base64) return toolError('The app returned an empty screenshot');
      return {
        content: [
          {
            type: 'image',
            data: base64,
            mimeType: shot?.mimeType || 'image/jpeg',
          },
        ],
      };
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
