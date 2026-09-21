# gods-eye-view-mcp

MCP server (stdio) that drives the [God's Eye View](https://github.com/bilawalsidhu/gods-eye-view)
app from any agent — the full voice-mode action vocabulary as `gev_*` tools,
plus app status, wait, and screenshot utilities.

See [docs/MCP-AGENT-BRIDGE.md](../docs/MCP-AGENT-BRIDGE.md) for the full guide.

## Install

```bash
npm install
```

## Run

```bash
# stdio server (point your MCP client at this)
node server.mjs

# with a non-default dev server URL
GEV_BASE_URL=http://localhost:4174 node server.mjs
```

The app must be running (`npm run dev` in the repo root) with a browser tab
open on it — the app long-polls the dev server's agent bridge for commands.

## Test

```bash
npm test
```

## Files

- `server.mjs` — the MCP server: registers one tool per voice action.
- `bridge.js` — HTTP client for the dev server's `/api/agent/*` endpoints.
- `schema-zod.js` — converts the app's action JSON schemas to zod.
- `descriptions.js` — agent-facing wording for every tool.
- `test/` — unit tests (`node --test "test/*.test.mjs"`).

## End-to-end test

`node mcp/e2e.mjs` opens the real app in headless Chrome and drives the full
chain (bridge → app → result): ping, `get_current_view_state`, screenshot,
and rejection of unknown commands. Requires the dev server running
(`npm run dev`).
