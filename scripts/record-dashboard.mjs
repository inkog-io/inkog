// Capture a full-page screenshot of an Inkog public scan report.
// Used to produce docs/screenshots/dashboard-report.png for the README.
//
// Usage:
//   node scripts/record-dashboard.mjs <report-url> <output-path>

import { chromium } from 'playwright';

const url = process.argv[2];
const out = process.argv[3] || 'docs/screenshots/dashboard-report.png';

if (!url) {
  console.error('Usage: node record-dashboard.mjs <report-url> [output-path]');
  process.exit(1);
}

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1280, height: 1800 },
  deviceScaleFactor: 2,
});
const page = await context.newPage();

console.log(`Loading ${url}…`);
await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 });

// Wait for findings to render (client-side React fetches them post-load).
// Match either the report's section headers or the gated-finding cards.
try {
  await page.waitForFunction(
    () => /EXPLOITABLE|VULNERABILIT|CRITICAL|HIGH|Governance/i.test(document.body.innerText),
    { timeout: 20000 }
  );
} catch (e) {
  console.error('Timed out waiting for finding content to render');
  console.error('Current page text head:', (await page.locator('body').innerText()).slice(0, 200));
  await browser.close();
  process.exit(2);
}

await page.waitForTimeout(1000);

await page.screenshot({ path: out, fullPage: true });
console.log(`Wrote ${out}`);
await browser.close();
