'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, '../electron/windows.cjs'), 'utf8');

// Execute the public API with a mocked process boundary. Tests never start
// Defender scans or modify Windows settings.
function load(execFile, platform = 'win32') {
  const module = { exports: {} };
  vm.runInNewContext(source, {
    module,
    Buffer,
    process: { platform, env: { SystemRoot: 'C:\\Windows' } },
    require: name => name === 'node:child_process' ? { execFile } : require(name),
  });
  return module.exports;
}

function reply(value, inspect = () => {}) {
  return (executable, args, options, callback) => {
    inspect(executable, args, options);
    callback(null, '\uFEFF' + JSON.stringify(value));
  };
}

test('unknown Defender values stay unknown; independent check failures do not look healthy', async () => {
  const app = load(reply({
    defender: { available: true, antivirusEnabled: false, realTimeEnabled: null, signatureAgeDays: 65535, quickScanAt: '1601-01-01T00:00:00Z' },
    firewall: { available: false, error: 'Access is denied.' },
    threats: { available: true, items: [] },
  }));
  const result = await app.getSystemStatus();
  assert.equal(result.defender.available, true);
  assert.equal(result.defender.antivirusEnabled, false);
  assert.equal(result.defender.realTimeEnabled, null);
  assert.equal(result.defender.behaviorMonitorEnabled, null);
  assert.equal(result.defender.signatureAgeDays, null);
  assert.equal(result.defender.quickScanAt, null);
  assert.equal(result.firewall.available, false);
  assert.match(result.firewall.error, /denied/);
  assert.equal(result.threats.available, true);
  assert.equal(result.threats.items.length, 0);
});

test('normalizes singleton arrays, severity and UTC dates without hiding disabled controls', async () => {
  const app = load(reply({
    defender: { available: true, antivirusEnabled: true, realTimeEnabled: false, signatureAgeDays: 2, signaturesUpdatedAt: '2026-11-01T12:00:00+01:00' },
    firewall: { available: true, profiles: { name: 'Public', enabled: false } },
    threats: { available: true, items: { id: '42', name: 'Test threat', severity: 4, active: true, resources: 'file:C:\\fixture' } },
  }));
  const result = await app.getSystemStatus();
  assert.equal(result.defender.realTimeEnabled, false);
  assert.equal(result.defender.signaturesUpdatedAt, '2026-11-01T11:00:00.000Z');
  assert.equal(result.defender.signatureAgeDays, 2);
  assert.equal(result.firewall.profiles[0].enabled, false);
  assert.equal(result.threats.items[0].severity, 'severe');
  assert.equal(result.threats.items[0].resources[0], 'file:C:\\fixture');
});

test('uses absolute PowerShell, encoded fixed commands and bounded hidden execution', async () => {
  const app = load(reply({ available: true, connections: [] }, (executable, args, options) => {
    assert.equal(executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.ok(args.includes('-NoProfile'));
    assert.ok(args.includes('-NonInteractive'));
    const script = Buffer.from(args[args.indexOf('-EncodedCommand') + 1], 'base64').toString('utf16le');
    assert.match(script, /Get-NetTCPConnection/);
    assert.match(script, /Established/);
    assert.match(script, /Select-Object -First 150/);
    assert.equal(options.windowsHide, true);
    assert.equal(options.timeout, 30000);
    assert.equal(options.encoding, 'utf8');
    assert.equal(options.env.PSModulePath, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules');
  }));
  const result = await app.getConnections();
  assert.equal(result.available, true);
  assert.equal(result.connections.length, 0);
});

test('connection snapshots preserve unknown owners and cap the returned list', async () => {
  const app = load(reply({ available: true, connections: Array.from({ length: 160 }, (_, n) => ({ pid: n, remoteAddress: '127.0.0.1', remotePort: 443, state: 'Established' })) }));
  const result = await app.getConnections();
  assert.equal(result.connections.length, 150);
  assert.equal(result.connections[0].process, 'Unknown process');
  assert.equal(result.connections[0].localPort, null);
});

test('malformed process output never becomes an empty successful health report', async () => {
  const app = load((executable, args, options, callback) => callback(null, 'unexpected output'));
  const result = await app.getSystemStatus();
  assert.equal(result.defender.available, false);
  assert.equal(result.defender.realTimeEnabled, null);
  assert.equal(result.firewall.available, false);
  assert.equal(result.threats.available, false);
});

test('scan timeouts report an unknown outcome and leave scan completion unclaimed', async () => {
  const app = load((executable, args, options, callback) => {
    assert.equal(options.timeout, 600000);
    callback(Object.assign(new Error('not displayed'), { killed: true }), '');
  });
  const result = await app.runDefenderScan();
  assert.equal(result.ok, false);
  assert.equal(result.completed, false);
  assert.match(result.message, /may still be running/);
  assert.match(result.message, /10 minutes/);
});

test('scan permissions errors pass through accurately', async () => {
  const app = load(reply({ ok: false, message: 'Access is denied. Run with administrator permissions.' }));
  const result = await app.runDefenderScan();
  assert.equal(result.ok, false);
  assert.equal(result.message, 'Access is denied. Run with administrator permissions.');
  assert.equal(result.completed, false);
});

test('duplicate scan requests are rejected while the first is pending', async () => {
  let complete;
  const app = load((executable, args, options, callback) => { complete = callback; });
  const initial = app.runDefenderScan();
  const duplicate = await app.runDefenderScan();
  assert.equal(duplicate.ok, false);
  assert.equal(duplicate.completed, false);
  assert.match(duplicate.message, /already/);
  complete(null, JSON.stringify({ ok: true, completed: true, message: 'Completed.' }));
  const result = await initial;
  assert.equal(result.ok, true);
  assert.equal(result.completed, true);
});

test('an accepted scan request is distinct from confirmed completion', async () => {
  const app = load(reply({ ok: true, completed: false, message: 'Accepted.' }));
  const result = await app.runDefenderScan();
  assert.equal(result.ok, true);
  assert.equal(result.completed, false);
});

test('missing completion evidence and unsuccessful requests never report completion', async () => {
  for (const response of [{ ok: true }, { ok: false, completed: true }]) {
    const app = load(reply(response));
    assert.equal((await app.runDefenderScan()).completed, false);
  }
});

test('file inspection hashes literal paths, transports them as data and never executes file contents', async () => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'atguard-file-test-'));
  const chosenPath = path.join(directory, "sample [x]'; $(literal).txt");
  const contents = 'ATGuard benign file-inspection fixture.\n';
  try {
    await fsp.writeFile(chosenPath, contents);
    const app = load(reply({ status: 'NotSigned', signer: null }, (executable, args, options) => {
      const script = Buffer.from(args[args.indexOf('-EncodedCommand') + 1], 'base64').toString('utf16le');
      assert.equal(options.env.ATGUARD_INSPECT_PATH, chosenPath);
      assert.ok(!script.includes(chosenPath));
      assert.match(script, /Get-AuthenticodeSignature -LiteralPath \$env:ATGUARD_INSPECT_PATH/);
    }));
    const result = await app.inspectFile(chosenPath);
    assert.equal(result.sha256, createHash('sha256').update(contents).digest('hex'));
    assert.equal(result.size, Buffer.byteLength(contents));
    assert.equal(result.signature.status, 'NotSigned');
    assert.equal(result.signature.signer, null);
    assert.match(result.note, /do not establish that a file is safe/);
    await assert.rejects(app.inspectFile('relative.txt'), /file picker/);
    await assert.rejects(app.inspectFile(directory), /regular file/);
  } finally {
    // Only remove the known fixture and empty temporary directory.
    await fsp.unlink(chosenPath).catch(() => {});
    await fsp.rmdir(directory);
  }
});
