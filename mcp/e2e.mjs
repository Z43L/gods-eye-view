/** E2E: headless Chrome opens the app, then commands flow bridge -> app -> result. */
import puppeteer from 'puppeteer';

const BASE = 'http://localhost:4173';
const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(
    `${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`,
  );
};

const browser = await puppeteer.launch({
  headless: 'new',
  args: [
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--use-gl=angle',
    '--use-angle=swiftshader',
    '--enable-unsafe-swiftshader',
  ],
});
const page = await browser.newPage();
await page.setViewport({ width: 1280, height: 800 });
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push(String(e).split('\n')[0]));

await page.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 60000 });
check('page loads', true);

// Wait for the agent channel to connect (app boot + first heartbeat).
let connected = false;
for (let i = 0; i < 40; i++) {
  await new Promise((r) => setTimeout(r, 3000));
  const status = await fetch(`${BASE}/api/agent/status`).then((r) => r.json());
  if (status.connected) {
    connected = true;
    break;
  }
}
check('app connects to agent bridge', connected);
if (!connected) {
  console.log('page errors:', pageErrors.slice(0, 5));
  await browser.close();
  process.exit(1);
}

async function runCommand(name, args = {}, timeoutMs = 60000) {
  const queued = await fetch(`${BASE}/api/agent/command`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, args }),
  }).then((r) => r.json());
  if (!queued?.id)
    throw new Error('bridge refused command: ' + JSON.stringify(queued));
  const outcome = await fetch(
    `${BASE}/api/agent/result/${queued.id}?waitMs=${timeoutMs}`,
  ).then((r) => (r.status === 204 ? null : r.json()));
  return outcome;
}

// 1. Synthetic ping through the whole chain.
const ping = await runCommand('ping');
check('ping round-trip', ping?.ok === true && ping?.result?.pong === true);

// 2. A real voice action: read the current view state.
const view = await runCommand('get_current_view_state');
check(
  'get_current_view_state executes',
  view?.ok === true && view?.result != null,
  view?.ok ? 'result keys: ' + Object.keys(view.result).join(',') : view?.error,
);

// 3. Screenshot through the whole chain.
const shot = await runCommand('capture_screenshot');
const dataUrl = shot?.result?.dataUrl || '';
check(
  'capture_screenshot returns JPEG',
  shot?.ok === true && dataUrl.startsWith('data:image/jpeg;base64,/9j/'),
  `length=${dataUrl.length}`,
);

// 4. Unknown command is rejected at the bridge (never reaches the app).
const bad = await fetch(`${BASE}/api/agent/command`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'launch_missiles', args: {} }),
});
check('unknown command rejected', bad.status === 400);

console.log('page errors during run:', pageErrors.slice(0, 5));
await browser.close();
const failed = results.filter((r) => !r.ok);
process.exit(failed.length ? 1 : 0);
