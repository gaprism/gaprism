/** Real-browser regression checks using Chromium's protocol and Node's built-in WebSocket. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const base = process.env.PREVIEW_URL || 'http://127.0.0.1:5055';
assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(base).hostname));
const browserPath = process.env.BROWSER_PATH || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
await access(browserPath);
const output = resolve('.local/verification');
const profile = resolve('.local/browser-profiles', String(Date.now()));
await mkdir(output, { recursive: true });
await mkdir(profile, { recursive: true });
const browser = spawn(browserPath, ['--headless=new', '--no-first-run', '--no-default-browser-check',
  '--disable-background-networking', '--disable-component-update', '--disable-sync',
  '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
  { windowsHide: true, stdio: 'ignore' });
let socket;
const pending = new Map();
const errors = [];
const externalRequests = [];
let seq = 0;
let checks = 0;
async function until(predicate, message) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await predicate()) return;
    await delay(100);
  }
  throw new Error(`Timed out: ${message}`);
}
function call(method, params = {}) {
  const id = ++seq;
  return new Promise((resolveCall, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Timed out: ${method}`)); }, 15000);
    pending.set(id, { resolve: (value) => { clearTimeout(timer); resolveCall(value); },
      reject: (error) => { clearTimeout(timer); reject(error); } });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const response = await call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (response.exceptionDetails) throw new Error(JSON.stringify(response.exceptionDetails));
  return response.result.value;
}
async function navigate(path, width = 1280, height = 900) {
  await call('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  await call('Page.navigate', { url: base + path });
  await until(() => evaluate(`location.pathname === ${JSON.stringify(path.split('?')[0])} && document.readyState === 'complete'`), path);
  await evaluate('document.fonts.ready.then(() => true)');
}
async function screenshot(name) {
  const result = await call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  await writeFile(`${output}/${name}.png`, Buffer.from(result.data, 'base64'));
}
try {
  let port;
  await until(async () => {
    try { port = (await readFile(`${profile}/DevToolsActivePort`, 'utf8')).split('\n')[0]; return true; }
    catch { return false; }
  }, 'browser startup');
  const pages = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(pages.find((page) => page.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolveOpen, reject) => { socket.onopen = resolveOpen; socket.onerror = reject; });
  socket.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.id) {
      const item = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) item?.reject(message.error); else item?.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params);
    if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') errors.push(message.params.entry);
    if (message.method === 'Network.requestWillBeSent') {
      const url = message.params.request.url;
      if (!url.startsWith(base) && !url.startsWith('data:')) externalRequests.push(url);
    }
  };
  await call('Page.enable');
  await call('Runtime.enable');
  await call('Log.enable');
  await call('Network.enable');
  const views = ['overview', 'infrastructure', 'providers', 'security', 'evidence', 'reports', 'sharing', 'cases', 'components', 'new', 'access'];
  for (const width of [320, 768, 1280, 1680]) {
    for (const view of views) {
      await navigate(`/preview/de-CH/${view}`, width);
      const metrics = await evaluate(`({page:document.documentElement.scrollWidth,width:innerWidth,title:document.querySelector('h1')?.textContent,ids:[...document.querySelectorAll('[id]')].map(e=>e.id)})`);
      assert(metrics.title, `${view} title missing`);
      assert(metrics.page <= metrics.width + 1, `${view} overflows at ${width}: ${metrics.page}`);
      assert.equal(new Set(metrics.ids).size, metrics.ids.length, `duplicate IDs: ${view}`);
      checks++;
    }
  }
  await navigate('/preview/de-CH/overview', 1280);
  await screenshot('overview-de-desktop');
  await navigate('/preview/de-CH/infrastructure', 1680);
  await evaluate(`document.querySelector('[data-host-link]').click()`);
  await until(() => evaluate(`document.activeElement === document.querySelector('#host-inspector h2')`), 'inspector focus');
  await screenshot('hosts-de-wide');
  await evaluate(`document.querySelector('[data-close-inspector]').click()`);
  assert(await evaluate(`document.activeElement.hasAttribute('data-last-host')`)); checks++;
  await evaluate(`document.getElementById('q').value='files'; document.getElementById('q').focus(); document.querySelector('form').requestSubmit()`);
  await until(() => evaluate(`document.querySelectorAll('#host-results tbody tr').length === 1 && location.search.includes('files')`), 'HTMX filter');
  assert.equal(await evaluate(`document.activeElement.id`), 'q');
  assert.equal(await evaluate(`document.querySelectorAll('#host-results').length`), 1); checks++;
  await evaluate(`document.getElementById('q').value='api'; document.querySelector('form').requestSubmit(); document.getElementById('q').value='status'; document.querySelector('form').requestSubmit()`);
  await until(() => evaluate(`document.querySelector('#host-results').textContent.includes('status.example.com') && !document.querySelector('#host-results').textContent.includes('api.example.com')`), 'latest filter wins'); checks++;
  await call('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  await evaluate(`document.getElementById('q').value='files'; document.querySelector('form').requestSubmit()`);
  await until(() => evaluate(`!document.getElementById('refresh-error').hidden`), 'failed refresh notice');
  assert(await evaluate(`document.querySelector('#host-results').textContent.includes('status.example.com')`)); checks++;
  await call('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  await navigate('/preview/de-CH/components', 1280);
  await evaluate(`document.querySelector('[data-dialog]').click()`);
  assert(await evaluate(`document.querySelector('dialog').open && document.activeElement.textContent.trim() === 'Abbrechen'`));
  await call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await until(() => evaluate(`!document.querySelector('dialog').open && document.activeElement.hasAttribute('data-dialog')`), 'dialog close focus'); checks++;
  const contrasts = await evaluate(`(() => {
    const lum = c => {const a=c.match(/[\\d.]+/g).slice(0,3).map(Number).map(v=>v/255).map(v=>v<=0.04045?v/12.92:((v+0.055)/1.055)**2.4);return a[0]*0.2126+a[1]*0.7152+a[2]*0.0722};
    return [...document.querySelectorAll('.badge,.btn-primary,.btn-secondary,.btn-destructive')].filter(e=>!e.disabled).map(e=>{const s=getComputedStyle(e);const a=lum(s.color),b=lum(s.backgroundColor);return {text:e.textContent.trim(),ratio:(Math.max(a,b)+0.05)/(Math.min(a,b)+0.05)}});
  })()`);
  assert(contrasts.every(item => item.ratio >= 4.5), JSON.stringify(contrasts)); checks++;
  await screenshot('components-de-desktop');
  await navigate('/preview/de-CH/overview', 320);
  await screenshot('overview-de-mobile');
  await navigate('/preview/en/infrastructure', 1280);
  await evaluate(`document.querySelector('[data-host-link]').click()`);
  await until(() => evaluate(`location.pathname.includes('/host/') && document.querySelector('h2')?.textContent.includes('api.example.com')`), 'narrow host full page'); checks++;
  await call('Emulation.setScriptExecutionDisabled', { value: true });
  await navigate('/preview/en/infrastructure?q=files', 1280);
  assert.equal(await evaluate(`document.querySelectorAll('tbody tr').length`), 1); checks++;
  await call('Emulation.setScriptExecutionDisabled', { value: false });
  for (const locale of ['en', 'de-CH']) {
    await navigate(`/preview/${locale}/report/DEMO-R01/print`, 1000, 1000);
    assert(await evaluate(`document.fonts.check('12px "Evidence Sans"')`));
    const pdf = await call('Page.printToPDF', { printBackground: true, preferCSSPageSize: true, displayHeaderFooter: false });
    await writeFile(`${output}/report-${locale}.pdf`, Buffer.from(pdf.data, 'base64'));
    await screenshot(`report-${locale}-screen`); checks++;
  }
  // Missing favicon is not a product error; it is still served from the local origin.
  const actionableErrors = errors.filter(e => !(e.url?.endsWith('/favicon.ico') && e.text?.includes('404'))
    && !e.text?.includes('net::ERR_INTERNET_DISCONNECTED'));
  assert.deepEqual(actionableErrors, [], JSON.stringify(actionableErrors));
  assert.deepEqual(externalRequests, []);
  await writeFile(`${output}/browser-results.json`, JSON.stringify({ checks, widths: [320,768,1280,1680], contrasts, errors: actionableErrors, externalRequests }, null, 2));
  console.log(`Passed ${checks} browser checks; screenshots and PDFs in ${output}`);
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ id: ++seq, method: 'Browser.close' }));
    socket.close();
  } else browser.kill();
}
