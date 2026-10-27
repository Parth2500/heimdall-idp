// Runs one OpenID conformance plan against a local Heimdall (issue #20). See README.md.
// The suite gives the URLs that a user must visit. Playwright visits them, signs in at Heimdall, confirms a sign-out
// when Heimdall asks, and uploads a screenshot when a module waits for a person's review.
//
// Usage: node run-plan.mjs <plan> <variant JSON> <config JSON file> [module filter]
// Trust the suite's certificate with NODE_EXTRA_CA_CERTS=../../.local/conformance/suite.crt. TLS checks stay on.
import { chromium } from 'playwright';
import fs from 'node:fs';

const SUITE = process.env.CONFORMANCE_SERVER ?? 'https://localhost.emobix.co.uk:8443/api/';
const [plan, variantJson, configFile, only] = process.argv.slice(2);
const EMAIL = process.env.HEIMDALL_CONFORMANCE_EMAIL;
const PASSWORD = process.env.HEIMDALL_CONFORMANCE_PASSWORD;
const CHROMIUM = process.env.CHROMIUM_PATH;
if (!plan || !configFile || !EMAIL || !PASSWORD) {
  console.error('Set HEIMDALL_CONFORMANCE_EMAIL and HEIMDALL_CONFORMANCE_PASSWORD, and pass a plan and a config file.');
  process.exit(2);
}

async function api(method, path, body) {
  const response = await fetch(SUITE + path, { method, body, headers: body ? { 'content-type': 'application/json' } : {} });
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${path}: ${response.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

let lastScreenshot = null;

async function visit(context, url) {
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: 'load', timeout: 20000 }).catch(() => {});
    for (let step = 0; step < 6; step++) {
      await page.waitForTimeout(1500);
      const now = page.url();
      if (now.includes('/account/login?')) {
        await page.getByLabel('Email').fill(EMAIL);
        await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
        await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      } else if (now.includes('/account/logout')) {
        await page.getByRole('button', { name: 'Sign out' }).click();
      } else {
        break;
      }
    }
    // The suite asks for a screenshot of what the user saw, when the result needs a person's review.
    lastScreenshot = 'data:image/png;base64,' + (await page.screenshot()).toString('base64');
    return page.url();
  } finally {
    await page.close();
  }
}

(async () => {
  const config = fs.readFileSync(configFile, 'utf8');
  const created = await api('POST', `plan?planName=${encodeURIComponent(plan)}&variant=${encodeURIComponent(variantJson)}`, config);
  console.log('plan', created.id);
  const browser = await chromium.launch(CHROMIUM ? { executablePath: CHROMIUM } : {});
  const results = [];
  for (const module of created.modules) {
    if (only && !module.testModule.includes(only)) continue;
    // A fresh browser for each module: each test starts with no Heimdall session, as the suite expects.
    // The test browser accepts the development certificates, which name neither acme.localhost nor the suite host.
    // Local tooling only. Heimdall and the suite still check TLS on their own calls.
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const variant = module.variant ? `&variant=${encodeURIComponent(JSON.stringify(module.variant))}` : '';
    const test = await api('POST', `runner?test=${encodeURIComponent(module.testModule)}&plan=${created.id}${variant}`);
    const visited = new Set();
    const uploaded = new Set();
    let info;
    for (let i = 0; i < 150; i++) {
      info = await api('GET', `info/${test.id}`);
      if (['FINISHED', 'INTERRUPTED'].includes(info.status)) break;
      if (info.status === 'WAITING') {
        const b = await api('GET', `runner/browser/${test.id}`);
        for (const url of b.urls ?? []) {
          if (visited.has(url)) continue;
          visited.add(url);
          await api('POST', `runner/browser/${test.id}/visit?url=${encodeURIComponent(url)}`);
          await visit(context, url);
        }

        // A WAITING test with nothing left to visit waits for a screenshot (its placeholder in the log).
        if (i % 5 === 4 && lastScreenshot) {
          const log = await api('GET', `log/${test.id}`);
          for (const entry of log.filter((e) => e.upload && !uploaded.has(e.upload))) {
            uploaded.add(entry.upload);
            await fetch(SUITE + `log/${test.id}/images/${entry.upload}`, { method: 'POST', body: lastScreenshot, headers: { 'content-type': 'text/plain' } });
          }
        }
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    let failures = [];
    if (info.result !== 'PASSED') {
      const log = await api('GET', `log/${test.id}`);
      failures = log
        .filter((e) => ['FAILURE', 'WARNING'].includes(e.result))
        .map((e) => `${e.result}: ${e.src}: ${e.msg}`)
        .slice(0, 4);
    }
    await context.close();
    results.push({ module: module.testModule, status: info.status, result: info.result, failures });
    console.log(`${info.result ?? info.status}\t${module.testModule}`);
    for (const f of failures) console.log('    ' + f.slice(0, 260));
  }
  fs.writeFileSync(`${process.env.OUT ?? '.'}/results-${plan}.json`, JSON.stringify(results, null, 2));
  await browser.close();
})().catch((e) => {
  console.error('FAILED', e.message);
  process.exit(1);
});
