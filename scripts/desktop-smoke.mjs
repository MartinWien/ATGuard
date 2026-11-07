import { _electron as electron } from '@playwright/test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';

// Run against our own application in an isolated profile. Only read-only system
// checks are exercised; starting Defender, changing Windows settings and actual
// dialogs are intentionally excluded from automated smoke tests.
const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'atguard-smoke-'));
const packaged = process.argv.includes('--packaged');
const executablePath = packaged ? path.resolve('release/win-unpacked/ATGuard.exe') : undefined;
const errors = [];
let app;
try {
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  app = await electron.launch({ executablePath, args: [...(packaged ? [] : ['.']), `--user-data-dir=${profile}`], env, timeout: 30000 });
  const page = await app.firstWindow();
  page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('heading', { name: 'A safer digital everyday.' }).waitFor();
  await page.getByText('On-device protection', { exact: true }).waitFor();
  const prefs = await app.evaluate(({ BrowserWindow }) => {
    const p = BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences();
    return { sandbox: p.sandbox, nodeIntegration: p.nodeIntegration, contextIsolation: p.contextIsolation, webSecurity: p.webSecurity };
  });
  assert.deepEqual(prefs, { sandbox: true, nodeIntegration: false, contextIsolation: true, webSecurity: true });
  assert.equal(await page.evaluate(() => typeof window.require), 'undefined');
  await page.getByRole('button', { name: 'Refresh status', exact: true }).waitFor({ state: 'visible', timeout: 45000 });
  const actual = await page.evaluate(() => window.atguard.getSystemStatus());
  assert.equal(actual.platform, 'win32');
  assert.equal(typeof actual.defender.available, 'boolean');
  assert.equal(typeof actual.firewall.available, 'boolean');
  await fs.mkdir('artifacts', { recursive: true });
  await page.screenshot({ path: 'artifacts/ATGuard-overview.png' });
  await page.getByRole('button', { name: 'Link inspector', exact: true }).click();
  await page.getByLabel('Website address').fill('https://paypal.com.account-check.example/verify');
  await page.getByRole('button', { name: 'Inspect link', exact: true }).click();
  await page.getByRole('heading', { name: 'Strong warning signs detected' }).waitFor();
  await page.getByLabel('Website address').fill('https://example.com');
  assert.equal(await page.getByRole('heading', { name: 'Strong warning signs detected' }).count(), 0);
  await page.getByRole('button', { name: 'Inspect link', exact: true }).click();
  await page.getByRole('heading', { name: 'No obvious warning signs' }).waitFor();
  await page.getByRole('button', { name: 'Scam checker', exact: true }).click();
  await page.getByLabel('Message to check').fill('Urgent: I am your bank. Send your password and verification code immediately.');
  await page.getByRole('button', { name: 'Check message', exact: true }).click();
  await page.getByRole('heading', { name: 'Strong warning signs detected' }).waitFor();
  await page.getByRole('button', { name: 'Activity log', exact: true }).click();
  assert.equal(await page.getByRole('heading', { name: 'Link inspected', exact: true }).count(), 2);
  assert.equal(await page.getByText('Urgent: I am your bank.', { exact: false }).count(), 0);
  await page.getByRole('button', { name: 'Network activity', exact: true }).click();
  await page.getByRole('button', { name: 'Refresh connections', exact: true }).waitFor({ timeout: 45000 });
  assert.ok((await page.locator('tbody tr').count()) > 0 || await page.getByText('No established connections reported', { exact: true }).count() > 0 || await page.getByText('Network snapshot unavailable', { exact: true }).count() > 0);
  await page.getByRole('button', { name: 'Security scan', exact: true }).click();
  await page.getByRole('button', { name: 'Start malware scan', exact: true }).click();
  await page.getByRole('dialog').waitFor();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  assert.equal(await page.getByRole('dialog').count(), 0);
  const fixturePath = path.join(profile, 'inspection-fixture.txt');
  const fixtureContent = 'ATGuard local file inspection test.\n';
  await fs.writeFile(fixturePath, fixtureContent);
  await app.evaluate(({ dialog }, filePath) => {
    dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [filePath] });
  }, fixturePath);
  await page.getByRole('button', { name: 'Overview', exact: true }).click();
  await page.getByRole('button', { name: /Know your downloads/ }).click();
  await page.getByRole('dialog').waitFor({ timeout: 45000 });
  await page.getByRole('heading', { name: 'inspection-fixture.txt' }).waitFor();
  const expectedHash = createHash('sha256').update(fixtureContent).digest('hex');
  assert.equal(await page.getByText(expectedHash, { exact: true }).count(), 1);
  await app.evaluate(({ clipboard }) => { clipboard.writeText = text => { clipboard.atguardTestValue = text; }; });
  await page.getByRole('button', { name: 'Copy fingerprint', exact: true }).click();
  await page.getByText('SHA-256 copied.', { exact: true }).waitFor();
  assert.equal(await app.evaluate(({ clipboard }) => clipboard.atguardTestValue), expectedHash);
  assert.match(await page.evaluate(() => window.atguard.copyFingerprint('invalid').catch(error => error.message)), /Invalid SHA-256/);
  await page.getByRole('button', { name: 'Close dialog', exact: true }).click();
  const reportPath = path.join(profile, 'report.json');
  await app.evaluate(({ dialog }, filePath) => {
    dialog.showSaveDialog = async () => ({ canceled: false, filePath });
  }, reportPath);
  await page.getByRole('button', { name: 'Activity log', exact: true }).click();
  await page.getByRole('button', { name: 'Export report', exact: true }).click();
  await page.getByText('Report saved to your chosen location.', { exact: true }).waitFor();
  const report = JSON.parse(await fs.readFile(reportPath, 'utf8'));
  assert.equal(report.application, 'ATGuard');
  assert.equal(report.activity.some(event => event.type === 'file'), true);
  assert.equal(report.system.platform, 'win32');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  const remember = page.getByRole('switch', { name: 'Remember activity on this device' });
  await remember.click();
  assert.equal(await remember.getAttribute('aria-checked'), 'false');
  await page.reload();
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  assert.equal(await remember.getAttribute('aria-checked'), 'false');
  await page.getByRole('button', { name: 'Activity log', exact: true }).click();
  await page.getByRole('heading', { name: 'Your story starts with a check.' }).waitFor();
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: true, packaged, rendererErrors: errors, sandbox: prefs, defenderAvailable: actual.defender.available, firewallAvailable: actual.firewall.available, fileInspection: 'passed', reportExport: 'passed', screenshot: path.resolve('artifacts/ATGuard-overview.png') }, null, 2));
} finally {
  if (app) await app.close();
  // Isolated test profile is left in OS temp for normal OS cleanup.
}
