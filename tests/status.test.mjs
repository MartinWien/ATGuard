import test from 'node:test';
import assert from 'node:assert/strict';
import { protectionChecks, overallStatus } from '../src/lib/status.js';

function knownGood() {
  return {
    defender: { available: true, antivirusEnabled: true, realTimeEnabled: true, behaviorMonitorEnabled: true, signatureAgeDays: 0 },
    firewall: { available: true, profiles: [{ name: 'Public', enabled: true }, { name: 'Private', enabled: true }, { name: 'Domain', enabled: true }] },
    threats: { available: true, items: [] },
  };
}

function check(status, id) {
  return protectionChecks(status).find(item => item.id === id);
}

test('a full set of reported healthy checks passes', () => {
  const checks = protectionChecks(knownGood());
  assert.equal(checks.length, 6);
  assert.ok(checks.every(item => item.state === 'good'));
  assert.equal(overallStatus(checks).label, 'Checks passed');
});

test('missing and all-unknown checks are explicitly distinguished from verified protection', () => {
  assert.equal(overallStatus(protectionChecks(null)).label, 'Not checked');
  for (const status of [{}, { defender: { available: true }, firewall: { available: true }, threats: { available: true } }]) {
    const checks = protectionChecks(status);
    assert.ok(checks.every(item => item.state === 'unknown'));
    assert.equal(overallStatus(checks).label, 'Not verified');
  }
});

test('null protection flags and missing signature age never pass', () => {
  const status = knownGood();
  status.defender.antivirusEnabled = null;
  status.defender.realTimeEnabled = null;
  status.defender.behaviorMonitorEnabled = null;
  status.defender.signatureAgeDays = null;
  for (const id of ['antivirus', 'realtime', 'behavior', 'signatures']) assert.equal(check(status, id).state, 'unknown');
  assert.equal(overallStatus(protectionChecks(status)).label, 'Partially verified');
});

test('disabled controls produce warnings and an active threat takes precedence', () => {
  const status = knownGood();
  status.defender.antivirusEnabled = false;
  status.defender.realTimeEnabled = false;
  status.defender.behaviorMonitorEnabled = false;
  status.firewall.profiles[0].enabled = false;
  for (const id of ['antivirus', 'realtime', 'behavior', 'firewall']) assert.equal(check(status, id).state, 'warning');
  assert.equal(overallStatus(protectionChecks(status)).state, 'warning');
  status.threats.items = [{ active: true }, { active: null }];
  assert.equal(check(status, 'threats').state, 'danger');
  assert.equal(overallStatus(protectionChecks(status)).label, 'Action needed');
});

test('unknown threat activity never produces a clean threat verdict', () => {
  for (const items of [[{ active: null }], [{}], [null], [{ active: false }, { active: null }], [{ active: 'false' }]]) {
    const status = knownGood();
    status.threats.items = items;
    const threatCheck = check(status, 'threats');
    assert.equal(threatCheck.state, 'unknown');
    assert.match(threatCheck.detail, /without a confirmed/);
    assert.equal(overallStatus(protectionChecks(status)).state, 'unknown');
  }
  const inactive = knownGood();
  inactive.threats.items = [{ active: false }];
  assert.equal(check(inactive, 'threats').state, 'good');
});

test('unavailable sources never pass even if they contain older healthy values', () => {
  for (const available of [false, null, undefined, 'true']) {
    const status = knownGood();
    status.defender.available = available;
    status.firewall.available = available;
    status.threats.available = available;
    assert.ok(protectionChecks(status).every(item => item.state === 'unknown'));
  }
});

test('partial or missing firewall profile states remain unknown', () => {
  for (const profiles of [[], null, [{ name: 'Public', enabled: null }], [{ enabled: true }, { enabled: null }], [null]]) {
    const status = knownGood();
    status.firewall.profiles = profiles;
    assert.equal(check(status, 'firewall').state, 'unknown');
  }
});

test('unknown and sentinel signature ages stay unknown; stale signatures warn', () => {
  for (const age of [null, undefined, '0', -1, Infinity, NaN, 65535, 4294967295]) {
    const status = knownGood();
    status.defender.signatureAgeDays = age;
    assert.equal(check(status, 'signatures').state, 'unknown');
  }
  const stale = knownGood();
  stale.defender.signatureAgeDays = 4;
  assert.equal(check(stale, 'signatures').state, 'warning');
});
