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
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { GEV_ACTION_SCHEMAS } from '../src/voice/actionSchemas.js';
import { actionInputShape } from './schema-zod.js';
import { createBridgeClient } from './bridge.js';
import {
  ACTION_DESCRIPTIONS,
  NETWORK_DESCRIPTIONS,
  RECON_DESCRIPTIONS,
  UTILITY_DESCRIPTIONS,
} from './descriptions.js';
import {
  triangulateNetwork,
  summarizeDossier,
} from '../server/network/triangulate.mjs';
import { getDefaultInventory } from '../server/network/inventory.mjs';
import { getDefaultReconDb } from '../server/recon/db.mjs';
import { fingerprintTarget } from '../server/recon/fingerprint.mjs';
import { runTraceroute } from '../server/recon/traceroute.mjs';
import { runDnsRecon } from '../server/recon/dnsRecon.mjs';

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

// --- Network inventory tools (passive triangulation + SQLite store) --------

server.registerTool(
  'network_triangulate',
  {
    description: NETWORK_DESCRIPTIONS.network_triangulate,
    inputSchema: {
      query: z
        .string()
        .min(1)
        .max(256)
        .describe('IP, hostname, BSSID, SSID or ASN to triangulate'),
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const dossier = await triangulateNetwork(args.query);
      return toolJson({ ok: true, dossier: summarizeDossier(dossier) });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

server.registerTool(
  'network_inventory_list',
  {
    description: NETWORK_DESCRIPTIONS.network_inventory_list,
    inputSchema: {
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe('Max networks to return (default 50)'),
    },
    annotations: { readOnlyHint: true },
  },
  async (args) => {
    try {
      const inventory = getDefaultInventory();
      const networks = inventory.listNetworks({ limit: args?.limit ?? 50 });
      return toolJson({ ok: true, count: networks.length, networks });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

// --- Active Reconnaissance & Threat Intel tools (SQLite store) -------------

server.registerTool(
  'recon_fingerprint',
  {
    description: RECON_DESCRIPTIONS.recon_fingerprint,
    inputSchema: {
      host: z.string().min(1).max(256).describe('Target IP or hostname to fingerprint'),
      targetType: z.string().optional().describe('Target category, e.g. cctv, radio, server'),
      ports: z.array(z.number().int()).optional().describe('Optional custom ports to probe (e.g. [80, 443, 554, 8080])'),
    },
    annotations: { openWorldHint: true },
  },
  async (args) => {
    try {
      const result = await fingerprintTarget({
        host: args.host,
        targetType: args.targetType || 'server',
        ports: args.ports || [80, 443, 554, 8080, 8443],
      });
      return toolJson({ ok: true, result });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

server.registerTool(
  'recon_traceroute',
  {
    description: RECON_DESCRIPTIONS.recon_traceroute,
    inputSchema: {
      target: z.string().min(1).max(256).describe('Target hostname or IP address to trace'),
      maxHops: z.number().int().min(1).max(30).optional().describe('Maximum hops to probe (default 20)'),
    },
    annotations: { openWorldHint: true },
  },
  async (args) => {
    try {
      const result = await runTraceroute({
        target: args.target,
        maxHops: args.maxHops ?? 20,
      });
      return toolJson({ ok: true, result });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

server.registerTool(
  'recon_dns_lookup',
  {
    description: RECON_DESCRIPTIONS.recon_dns_lookup,
    inputSchema: {
      domain: z.string().min(1).max(256).describe('Domain name or IP address for active DNS inspection'),
    },
    annotations: { openWorldHint: true },
  },
  async (args) => {
    try {
      const result = await runDnsRecon({ domain: args.domain });
      return toolJson({ ok: true, result });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

server.registerTool(
  'recon_inventory_query',
  {
    description: RECON_DESCRIPTIONS.recon_inventory_query,
    inputSchema: {
      targetId: z.string().optional().describe('Optional specific target ID to get full dossier for'),
      tag: z.string().optional().describe('Optional tag to filter targets'),
      limit: z.number().int().min(1).max(100).optional().describe('Max targets to return (default 50)'),
    },
    annotations: { readOnlyHint: true },
  },
  async (args) => {
    try {
      const db = getDefaultReconDb();
      if (args.targetId) {
        const dossier = db.getFullDossier(args.targetId);
        if (!dossier) return toolError(`Target "${args.targetId}" not found in SQLite reconnaissance store`);
        return toolJson({ ok: true, dossier });
      }
      const targets = db.listTargets({ limit: args.limit ?? 50, tag: args.tag });
      return toolJson({ ok: true, count: targets.length, targets });
    } catch (error) {
      return toolError(error?.message || String(error));
    }
  },
);

await server.connect(transport);
