#!/usr/bin/env node
/**
 * `npm run dev:tunnel` — start the dev server and expose it through a
 * Cloudflare quick tunnel, automatically.
 *
 * What it does:
 *   1. Picks the bridge token from `GEV_AGENT_TOKEN` (or `--token`), or
 *      generates a random one. The dev server is started with it, so remote
 *      agents must present it in the `x-gev-agent-token` header.
 *   2. Installs `cloudflared` on demand (Homebrew on macOS, direct download
 *      on Linux) when it is not already on PATH.
 *   3. Starts the vite dev server directly, waits for the agent bridge to
 *      answer (trying both ::1 and 127.0.0.1, since Vite may bind to ::1
 *      only), then opens `cloudflared tunnel --url <working-origin>`.
 *   4. Prints the public URL, the token, and the MCP command for the
 *      remote side.
 *
 * Usage:
 *   npm run dev:tunnel [-- --port 4173] [--token <secret>]
 *   PORT=4173 GEV_AGENT_TOKEN=<secret> npm run dev:tunnel
 *
 * Quick tunnels need no Cloudflare account, but the URL is random on every
 * run and public to anyone who knows it — the token is the protection.
 * Never commit the token.
 */

import { spawn, execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, stat } from 'node:fs/promises';
import { homedir, platform, arch } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  if (i >= 0 && args[i + 1]) return args[i + 1];
  return fallback;
};
const PORT = Number(flag('port', process.env.PORT)) || 4173;
let TOKEN = flag('token', process.env.GEV_AGENT_TOKEN) || '';
if (!TOKEN.trim()) {
  TOKEN = randomBytes(32).toString('hex');
  console.log('[tunnel] generated a random bridge token for this run');
}
TOKEN = TOKEN.trim();

const run = (cmd, cmdArgs, opts = {}) =>
  new Promise((resolve, reject) => {
    execFile(cmd, cmdArgs, opts, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
  });

async function whichCloudflared() {
  try {
    await run(process.platform === 'win32' ? 'where' : 'which', [
      'cloudflared',
    ]);
    return 'cloudflared';
  } catch {
    return null;
  }
}

async function installCloudflared() {
  const os = platform();
  if (os === 'darwin') {
    console.log('[tunnel] installing cloudflared via Homebrew…');
    await run('brew', ['install', 'cloudflared'], { stdio: 'inherit' });
    return 'cloudflared';
  }
  if (os === 'linux') {
    const machine = arch() === 'arm64' ? 'arm64' : 'amd64';
    const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${machine}`;
    const dir = join(homedir(), '.cache', 'gev-agent-bridge');
    const bin = join(dir, 'cloudflared');
    try {
      await stat(bin);
      console.log(`[tunnel] using cached cloudflared at ${bin}`);
      return bin;
    } catch {
      /* download it */
    }
    console.log(`[tunnel] downloading cloudflared (${machine})…`);
    await mkdir(dir, { recursive: true });
    await run('curl', ['-fsSL', '-o', bin, url], {
      stdio: 'inherit',
      timeout: 120000,
    });
    await chmod(bin, 0o755);
    return bin;
  }
  throw new Error(
    `automatic cloudflared install is not supported on ${os}; install it manually: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/`,
  );
}

async function waitForBridge(urls, timeoutMs = 90000) {
  // Vite may bind to ::1 only; try both loopbacks and return the one
  // that answers.
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const url of urls) {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(4000) });
        if (res.ok) return url;
      } catch {
        /* not up yet */
      }
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}

async function main() {
  const cloudflared =
    (await whichCloudflared()) || (await installCloudflared());

  console.log(`[tunnel] starting dev server on port ${PORT}…`);
  // Spawn the vite binary directly (not via `npm run dev`) so the child
  // we hold IS the server and SIGTERM reliably stops it — no orphans.
  const viteBin = join(root, 'node_modules', 'vite', 'bin', 'vite.js');
  const dev = spawn(process.execPath, [viteBin], {
    cwd: root,
    env: { ...process.env, PORT: String(PORT), GEV_AGENT_TOKEN: TOKEN },
    stdio: 'inherit',
  });
  const children = new Set([dev]);
  const shutdown = (code) => {
    for (const child of children) {
      try {
        child.kill('SIGTERM');
      } catch {
        /* already gone */
      }
    }
    process.exit(code);
  };
  process.on('SIGINT', () => shutdown(130));
  process.on('SIGTERM', () => shutdown(143));
  dev.on('exit', (code) => {
    console.error(`[tunnel] dev server exited (${code}); shutting down`);
    shutdown(code ?? 1);
  });

  const statusUrls = [
    `http://[::1]:${PORT}/api/agent/status`,
    `http://127.0.0.1:${PORT}/api/agent/status`,
  ];
  const liveBase = await waitForBridge(statusUrls);
  if (!liveBase) {
    console.error('[tunnel] dev server did not answer in time; aborting');
    shutdown(1);
    return;
  }
  // liveBase is like http://[::1]:4173/api/agent/status → origin for cloudflared
  const origin = liveBase.replace(/\/api\/agent\/status$/, '');
  console.log('[tunnel] dev server is up; opening Cloudflare tunnel…');

  const tunnel = spawn(
    cloudflared,
    ['tunnel', '--no-autoupdate', '--url', origin],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  children.add(tunnel);
  tunnel.on('exit', (code) => {
    console.error(`[tunnel] cloudflared exited (${code}); shutting down`);
    shutdown(code ?? 1);
  });

  let publicUrl = null;
  let printed = false;
  const sniff = (chunk) => {
    const text = chunk.toString();
    // Keep cloudflared's own log visible but quiet-ish.
    for (const line of text.split('\n')) {
      if (/ERR|error|failed/i.test(line))
        process.stderr.write(`[cloudflared] ${line}\n`);
    }
    // Match only the real tunnel URL on its own log line — never the
    // api.trycloudflare.com endpoint that appears in error messages.
    const match = text.match(
      /^[^\S\r\n]*https:\/\/(?!api\.)[a-z0-9-]+\.trycloudflare\.com[^\S\r\n]*$/m,
    );
    if (match && !publicUrl) {
      publicUrl = match[0];
      printSummary(publicUrl);
      printed = true;
    }
  };
  tunnel.stdout.on('data', sniff);
  tunnel.stderr.on('data', sniff);

  const watchdog = setTimeout(() => {
    if (!printed) {
      console.error(
        '[tunnel] no tunnel URL appeared after 60s — check the cloudflared log above',
      );
    }
  }, 60000);
  watchdog.unref();
}

function printSummary(publicUrl) {
  console.log('');
  console.log('  ═══════════════════════════════════════════════════════');
  console.log("   God's Eye View is live through Cloudflare:");
  console.log(`   ${publicUrl}`);
  console.log('  ═══════════════════════════════════════════════════════');
  console.log('');
  console.log('  Open that URL in a browser (the agent channel starts');
  console.log('  automatically).');
  console.log('');
  console.log('  ── Copy & paste this into your AI chat to connect ──');
  console.log(`  GEV_MCP_URL=${publicUrl}`);
  console.log(`  GEV_MCP_TOKEN=${TOKEN}`);
  console.log('  ───────────────────────────────────────────────────');
  console.log('');
  console.log('  …or run the MCP server yourself with:');
  console.log('');
  console.log(`    GEV_BASE_URL=${publicUrl} \\`);
  console.log(`    GEV_AGENT_TOKEN=${TOKEN} \\`);
  console.log('      npm run mcp   # (from the repo, on the agent side)');
  console.log('');
  console.log('  Keep this terminal open; Ctrl+C stops the dev server and');
  console.log('  the tunnel together.');
  console.log('');
}

main().catch((error) => {
  console.error(`[tunnel] ${error.message || error}`);
  process.exit(1);
});
