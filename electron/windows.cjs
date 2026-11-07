'use strict';

const { execFile } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

// These scripts are application constants. File paths are passed as environment
// data and consumed with -LiteralPath, never inserted into PowerShell source.
const PRELUDE = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
function To-IsoDate($value) {
  if ($null -eq $value) { return $null }
  try {
    $date = [datetime]$value
    if ($date.Year -lt 1970) { return $null }
    return $date.ToUniversalTime().ToString('o')
  } catch { return $null }
}
function To-NullableBool($value) {
  if ($null -eq $value) { return $null }
  if ($value -eq $true -or [string]$value -eq 'True') { return $true }
  if ($value -eq $false -or [string]$value -eq 'False') { return $false }
  return $null
}
`;

const STATUS_SCRIPT = String.raw`
$result = @{}
try {
  $status = Get-MpComputerStatus -ErrorAction Stop
  if ($null -eq $status) { throw 'Microsoft Defender returned no status.' }
  $age = $status.AntivirusSignatureAge
  if ($null -eq $age -or $age -lt 0 -or $age -ge 65535) { $age = $null }
  $result.defender = @{
    available = $true
    antivirusEnabled = To-NullableBool $status.AntivirusEnabled
    realTimeEnabled = To-NullableBool $status.RealTimeProtectionEnabled
    behaviorMonitorEnabled = To-NullableBool $status.BehaviorMonitorEnabled
    signaturesUpdatedAt = To-IsoDate $status.AntivirusSignatureLastUpdated
    signatureAgeDays = $age
    quickScanAt = To-IsoDate $status.QuickScanEndTime
  }
} catch {
  $result.defender = @{ available = $false; error = $_.Exception.Message }
}
try {
  $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
    @{ name = [string]$_.Name; enabled = To-NullableBool $_.Enabled }
  })
  if ($profiles.Count -eq 0) { throw 'Windows Firewall returned no profiles.' }
  $result.firewall = @{ available = $true; profiles = $profiles }
} catch {
  $result.firewall = @{ available = $false; profiles = @(); error = $_.Exception.Message }
}
try {
  $items = @(Get-MpThreat -ErrorAction Stop | ForEach-Object {
    @{
      id = [string]$_.ThreatID
      name = [string]$_.ThreatName
      severity = $_.SeverityID
      active = To-NullableBool $_.IsActive
      resources = @($_.Resources | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    }
  })
  $result.threats = @{ available = $true; items = $items }
} catch {
  $result.threats = @{ available = $false; items = @(); error = $_.Exception.Message }
}
$result | ConvertTo-Json -Depth 8 -Compress
`;

const CONNECTIONS_SCRIPT = String.raw`
try {
  # Filtering after enumeration avoids a CIM "not found" error on an idle host.
  $tcp = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Established' } |
    Sort-Object OwningProcess, RemoteAddress, RemotePort, LocalPort | Select-Object -First 150)
  $processNames = @{}
  $connections = @($tcp | ForEach-Object {
    $processId = [int]$_.OwningProcess
    if (-not $processNames.ContainsKey($processId)) {
      try { $processNames[$processId] = [string](Get-Process -Id $processId -ErrorAction Stop).ProcessName }
      catch { $processNames[$processId] = $null }
    }
    @{
      process = $processNames[$processId]
      pid = $processId
      localAddress = [string]$_.LocalAddress
      localPort = [int]$_.LocalPort
      remoteAddress = [string]$_.RemoteAddress
      remotePort = [int]$_.RemotePort
      state = [string]$_.State
    }
  })
  @{ available = $true; connections = $connections } | ConvertTo-Json -Depth 5 -Compress
} catch {
  @{ available = $false; connections = @(); error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`;

const SCAN_SCRIPT = String.raw`
try {
  $requestedAt = [datetime]::UtcNow
  Start-MpScan -ScanType QuickScan -ErrorAction Stop
  $completed = $false
  $message = 'Microsoft Defender accepted the quick scan request. Open Windows Security to confirm progress and results.'
  try {
    $scanStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($null -ne $scanStatus.QuickScanEndTime -and $scanStatus.QuickScanEndTime.ToUniversalTime() -ge $requestedAt) {
      $completed = $true
      $message = 'Microsoft Defender finished its quick scan. Review the refreshed protection status and Windows Security protection history for findings.'
    }
  } catch { }
  @{ ok = $true; completed = $completed; message = $message } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; completed = $false; message = $_.Exception.Message } | ConvertTo-Json -Compress
}
`;

const SIGNATURE_SCRIPT = String.raw`
try {
  $signature = Get-AuthenticodeSignature -LiteralPath $env:ATGUARD_INSPECT_PATH -ErrorAction Stop
  $signer = $null
  if ($null -ne $signature.SignerCertificate) { $signer = [string]$signature.SignerCertificate.Subject }
  @{ status = [string]$signature.Status; signer = $signer } | ConvertTo-Json -Compress
} catch {
  @{ status = 'Unknown'; signer = $null; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
`;

function plainText(value, fallback = '') {
  return typeof value === 'string' && value.trim() ? value.trim().slice(0, 4000) : fallback;
}

function nullableBool(value) {
  if (value === true || value === false) return value;
  return null;
}

function nullableNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function isoDate(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.getUTCFullYear() >= 1970 ? date.toISOString() : null;
}

function array(value) {
  return Array.isArray(value) ? value : value && typeof value === 'object' ? [value] : [];
}

function errorText(error) {
  if (error?.code === 'ENOENT') return 'Windows PowerShell is not available on this device.';
  if (error?.code === 'ATGUARD_TIMEOUT') return 'The Windows security check timed out. Try again or open Windows Security.';
  return plainText(error?.message, 'Windows did not return a result.');
}

function runPowerShell(script, { timeout = 30000, env = {} } = {}) {
  if (process.platform !== 'win32') return Promise.reject(new Error('This check requires Windows.'));
  const root = process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows';
  const executable = path.win32.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const encoded = Buffer.from(PRELUDE + script, 'utf16le').toString('base64');
  // A parent PowerShell 7 session can put incompatible modules ahead of the
  // Windows modules. Use only Windows' own modules for these system checks.
  const inheritedEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.toLowerCase() !== 'psmodulepath'));
  const childEnv = { ...inheritedEnv, ...env, PSModulePath: path.win32.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') };
  return new Promise((resolve, reject) => {
    execFile(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
      windowsHide: true,
      timeout,
      maxBuffer: 4 * 1024 * 1024,
      encoding: 'utf8',
      env: childEnv,
    }, (error, stdout) => {
      if (error) {
        // execFile's default error contains the full encoded command. Return a
        // concise diagnostic instead and keep command contents out of the UI.
        const failure = new Error(error.killed
          ? 'The Windows operation exceeded its wait limit.'
          : error.code === 'ENOENT'
            ? 'Windows PowerShell is not available on this device.'
            : `Windows PowerShell exited without a usable result (${error.code || error.signal || 'unknown error'}).`);
        failure.code = error.killed ? 'ATGUARD_TIMEOUT' : error.code;
        reject(failure);
        return;
      }
      try {
        const result = JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
        if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Unexpected result');
        resolve(result);
      } catch {
        reject(new Error('Windows returned an unreadable security result. Try again or open Windows Security.'));
      }
    });
  });
}

function unavailableStatus(message) {
  return {
    defender: { available: false, antivirusEnabled: null, realTimeEnabled: null, behaviorMonitorEnabled: null, signaturesUpdatedAt: null, signatureAgeDays: null, quickScanAt: null, error: message },
    firewall: { available: false, profiles: [], error: message },
    threats: { available: false, items: [], error: message },
  };
}

async function getSystemStatus() {
  let result;
  try {
    const raw = await runPowerShell(STATUS_SCRIPT);
    const defender = raw.defender || {};
    const firewall = raw.firewall || {};
    const threats = raw.threats || {};
    const severity = { 1: 'low', 2: 'moderate', 3: 'high', 4: 'severe' };
    const age = nullableNumber(defender.signatureAgeDays);
    result = {
      defender: {
        available: defender.available === true,
        antivirusEnabled: nullableBool(defender.antivirusEnabled),
        realTimeEnabled: nullableBool(defender.realTimeEnabled),
        behaviorMonitorEnabled: nullableBool(defender.behaviorMonitorEnabled),
        signaturesUpdatedAt: isoDate(defender.signaturesUpdatedAt),
        signatureAgeDays: age !== null && age < 65535 ? age : null,
        quickScanAt: isoDate(defender.quickScanAt),
        ...(defender.available !== true ? { error: plainText(defender.error, 'Microsoft Defender status is unavailable.') } : {}),
      },
      firewall: {
        available: firewall.available === true,
        profiles: array(firewall.profiles).map(profile => ({ name: plainText(profile.name, 'Unknown'), enabled: nullableBool(profile.enabled) })),
        ...(firewall.available !== true ? { error: plainText(firewall.error, 'Windows Firewall status is unavailable.') } : {}),
      },
      threats: {
        available: threats.available === true,
        items: array(threats.items).map((item, index) => ({
          id: plainText(item.id, `unknown-${index}`),
          name: plainText(item.name, 'Unknown threat'),
          severity: severity[item.severity] || 'unknown',
          active: nullableBool(item.active),
          resources: (Array.isArray(item.resources) ? item.resources : typeof item.resources === 'string' ? [item.resources] : []).filter(value => typeof value === 'string'),
        })),
        ...(threats.available !== true ? { error: plainText(threats.error, 'Microsoft Defender threat history is unavailable.') } : {}),
      },
    };
  } catch (error) {
    result = unavailableStatus(errorText(error));
  }
  return {
    platform: process.platform,
    hostname: os.hostname(),
    os: `${os.type()} ${os.release()}`,
    checkedAt: new Date().toISOString(),
    ...result,
  };
}

async function getConnections() {
  try {
    const raw = await runPowerShell(CONNECTIONS_SCRIPT);
    const connections = array(raw.connections).slice(0, 150).map((item, index) => {
      const localAddress = plainText(item.localAddress, 'Unknown');
      const remoteAddress = plainText(item.remoteAddress, 'Unknown');
      return {
        id: `${item.pid ?? 'unknown'}:${localAddress}:${item.localPort ?? ''}:${remoteAddress}:${item.remotePort ?? ''}:${index}`,
        process: plainText(item.process, 'Unknown process'),
        pid: nullableNumber(item.pid),
        localAddress,
        localPort: nullableNumber(item.localPort),
        remoteAddress,
        remotePort: nullableNumber(item.remotePort),
        state: plainText(item.state, 'Unknown'),
      };
    });
    return { available: raw.available === true, checkedAt: new Date().toISOString(), connections,
      ...(raw.available !== true ? { error: plainText(raw.error, 'Connection information is unavailable.') } : {}) };
  } catch (error) {
    return { available: false, checkedAt: new Date().toISOString(), connections: [], error: errorText(error) };
  }
}

let pendingScan = null;
async function runDefenderScan() {
  if (pendingScan) return { ok: false, completed: false, message: 'A Microsoft Defender quick scan is already being requested by ATGuard.' };
  pendingScan = runPowerShell(SCAN_SCRIPT, { timeout: 10 * 60 * 1000 });
  try {
    const raw = await pendingScan;
    return { ok: raw.ok === true, completed: raw.ok === true && raw.completed === true, message: plainText(raw.message, 'Microsoft Defender did not report a scan outcome. Open Windows Security to check progress.') };
  } catch (error) {
    if (error.code === 'ATGUARD_TIMEOUT') {
      return { ok: false, completed: false, message: 'ATGuard stopped waiting after 10 minutes. The Defender scan may still be running. Open Windows Security to check progress and results.' };
    }
    return { ok: false, completed: false, message: errorText(error) };
  } finally {
    pendingScan = null;
  }
}

async function inspectFile(filePath) {
  if (typeof filePath !== 'string' || !filePath || filePath.includes('\0') || !path.isAbsolute(filePath)) {
    throw new Error('Choose a file using the file picker.');
  }
  const resolved = await fs.realpath(filePath);
  const handle = await fs.open(resolved, 'r');
  let initial;
  let digest;
  try {
    initial = await handle.stat();
    if (!initial.isFile()) throw new Error('Choose a regular file to inspect.');
    const hash = createHash('sha256');
    const stream = handle.createReadStream({ autoClose: false });
    for await (const chunk of stream) hash.update(chunk);
    digest = hash.digest('hex');
    const afterHash = await handle.stat();
    if (initial.size !== afterHash.size || initial.mtimeMs !== afterHash.mtimeMs) {
      throw new Error('The file changed during inspection. Select it again after changes finish.');
    }
  } finally {
    await handle.close();
  }
  let signature;
  let signatureError;
  try {
    const raw = await runPowerShell(SIGNATURE_SCRIPT, { env: { ATGUARD_INSPECT_PATH: resolved } });
    signature = { status: plainText(raw.status, 'Unknown'), signer: plainText(raw.signer, null) };
    signatureError = plainText(raw.error);
  } catch (error) {
    signature = { status: 'Unknown', signer: null };
    signatureError = errorText(error);
  }
  const current = await fs.stat(resolved);
  if (initial.size !== current.size || initial.mtimeMs !== current.mtimeMs || initial.ino !== current.ino) {
    throw new Error('The file changed during inspection. Select it again after changes finish.');
  }
  const note = 'SHA-256 identifies the file; signature status identifies its publisher when available. These checks do not establish that a file is safe. ATGuard does not execute or upload the file.';
  return { name: path.basename(resolved), path: resolved, size: initial.size, sha256: digest, signature,
    note: signatureError ? `${note} Signature check: ${signatureError}` : note };
}

module.exports = { getSystemStatus, getConnections, runDefenderScan, inspectFile };
