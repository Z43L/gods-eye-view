# MCP Agent Bridge

Drive the entire God's Eye View app from any MCP-capable agent — the same
action vocabulary as voice mode, but over the Model Context Protocol.

## How it works

```
 Agent (Claude, Muse, …)
   │  MCP (stdio)
   ▼
 mcp/server.mjs ──HTTP──▶ dev server ──long-poll──▶ browser app
   29 gev_* tools        /api/agent/*              src/agent/channel.js
                         (loopback-only)           executes via the same
                                                   GEV action runner voice uses
```

Three pieces:

1. **`server/standalone/agentBridge.js`** — Vite dev-server plugin (dev only).
   Holds an in-memory command queue: the MCP server POSTs commands, the app
   long-polls for work and POSTs results back. All endpoints are
   loopback-only and refuse proxied requests.
2. **`src/agent/channel.js`** — app-side channel. Starts automatically in dev
   builds, polls the bridge, and executes commands through
   `createGevActionRunner` — the exact machinery behind voice mode.
   Also handles two synthetic commands: `ping` and `capture_screenshot`.
3. **`mcp/`** — the MCP server (stdio). One `gev_*` tool per voice action,
   with JSON-schema arguments converted from `src/voice/actionSchemas.js`
   (single source of truth), plus three utilities:
   `gev_app_status`, `gev_wait_for_app`, `gev_capture_screenshot`.

## Quick start

```bash
# 1. Install the MCP server's dependencies (once)
npm run mcp:install

# 2. Start the app (the bridge activates automatically in dev)
npm run dev

# 3. Open the app in a browser — it polls the bridge for commands
#    (append ?agent=0 to disable the bridge; ?agent=1 forces it on)
```

Then point your MCP client at the server:

```json
{
  "mcpServers": {
    "gods-eye-view": {
      "command": "node",
      "args": ["/absolute/path/to/gods-eye-view/mcp/server.mjs"],
      "env": {
        "GEV_BASE_URL": "http://localhost:4173"
      }
    }
  }
}
```

For Claude Code: `claude mcp add gods-eye-view -- node /absolute/path/to/gods-eye-view/mcp/server.mjs`.

## Environment

| Variable               | Default                  | Meaning                                              |
| ---------------------- | ------------------------ | ---------------------------------------------------- |
| `GEV_BASE_URL`         | `http://localhost:4173`  | Dev server URL the MCP server talks to               |
| `GEV_COMMAND_TIMEOUT_MS` | `120000`               | How long a tool waits for the app to finish          |

## Tools

Every voice-mode action is exposed as `gev_<action>` (29 tools):

Camera & navigation: `gev_fly_to_location`, `gev_select_nearest_aircraft`,
`gev_adjust_camera_zoom`, `gev_zoom_to_globe`, `gev_move_camera`,
`gev_fly_route`, `gev_frame_overhead`, `gev_track_entity`,
`gev_stop_tracking`, `gev_get_current_view_state`

Layers & data: `gev_set_layer_visibility`, `gev_show_data_layers_menu`,
`gev_get_entity_context`, `gev_analyst_query`, `gev_next_iss_pass`

Presentation: `gev_set_visual_style`, `gev_set_hud`, `gev_set_detection`,
`gev_set_map_stack`, `gev_set_post_processing`, `gev_set_panel_open`,
`gev_set_context_mode`

Media & scenes: `gev_control_cockpit`, `gev_control_scene`,
`gev_control_cctv`, `gev_control_radio`, `gev_annotate_map`,
`gev_clear_annotations`

Utilities: `gev_app_status`, `gev_wait_for_app`, `gev_capture_screenshot`

## Example session

> "Fly to Madrid, enable the flights layer, and show me what it looks like."

1. `gev_fly_to_location` `{ "query": "Madrid", "viewMode": "overview" }`
2. `gev_set_layer_visibility` `{ "layerId": "flights", "enabled": true }`
3. `gev_capture_screenshot` `{}` → the agent *sees* the globe.

## Notes & limits

- **Dev only.** The bridge endpoints install on `vite dev`, not on
  `vite preview` or production builds. The channel probes `/api/agent/status`
  first and stays silent when the endpoints are absent.
- **One app tab.** If two tabs poll, commands distribute between them; use one
  tab when driving the app from an agent.
- **Timeouts.** Camera flights with `waitForArrival` can take a while; raise
  `GEV_COMMAND_TIMEOUT_MS` if a tool times out on long flights.
- **Stale commands expire.** A command unclaimed for 5 minutes is dropped so a
  dead client can never fire it late.
- **Localhost only.** The bridge refuses non-loopback and proxied requests —
  it executes arbitrary app actions, so it must never be exposed to a network.
- **Tests.** `npm run mcp:test` (MCP package), plus
  `src/agent/bridgeQueue.test.mjs` in the repo suite (`npm test`).
