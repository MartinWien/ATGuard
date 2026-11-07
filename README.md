# ATGuard

A Windows desktop security companion with a black interface. ATGuard reads real protection settings, runs local scam-pattern checks, and gives you a clear place to review findings.

## Project direction

ATGuard is an early-stage project with the goal of helping Austrian companies recognize phishing attempts, scams, and suspicious requests for money or credentials. The plan is to develop it into a practical security companion for employees and small business teams, supported by clear explanations and visibility into Windows protection settings.

The current release provides the local inspection tools listed below. Company deployments and broader protection features are future goals.

## Run the desktop app

Download **[ATGuard for Windows](https://github.com/MartinWien/ATGuard/releases/download/v1.0.0/ATGuard-1.0.0-Windows.exe)** from the [v1.0.0 release](https://github.com/MartinWien/ATGuard/releases/tag/v1.0.0), then open it. This portable build does not require an installer.

For a local build, open `release/ATGuard-1.0.0-Windows.exe`. Alternatively, open `release/win-unpacked/ATGuard.exe` and keep its accompanying files together. Generated binaries are distributed as release assets and are not stored in Git.

The build is unsigned. No signing certificate or automatic update service is configured. Use your normal Windows trust controls; don't disable security protections to run it.

## Included features

- **Security overview:** actual Microsoft Defender antivirus, real-time protection, behavior monitoring, signature freshness, Windows Firewall profiles, and reported active threats. Missing information remains unverified.
- **Defender quick scan:** an explicit, user-triggered quick scan. Defender may remediate threats according to existing Windows policy. Successful requests and confirmed scan completion are shown separately. After ten minutes ATGuard stops waiting; Defender may still be scanning.
- **Link inspector:** offline address analysis for misleading user information, brand lookalikes, IP destinations, internationalized domains, short links, HTTP, and related patterns. Links are never visited or expanded.
- **Scam checker:** English-language text heuristics for urgent requests, passwords and one-time codes, payments, gift cards, remote access, and suspicious links. It analyzes at most the first 12 unique links in a message.
- **File inspection:** a local SHA-256 fingerprint and Windows Authenticode signature/publisher. The file is never executed or uploaded. Signature verification uses Windows trust APIs and may use OS certificate validation behavior.
- **Network activity:** a read-only snapshot of up to 150 established TCP connections, with process, PID, and endpoints. Filter and sort the snapshot.
- **Local activity and JSON reports:** up to 100 event summaries, optional persistence, export, and clearing. Message bodies and full URLs are not recorded in history; inspected hostnames and file names may appear.
- **Preferences:** optional status refresh every 60 seconds while open; local activity persistence on/off.

## Scope

ATGuard complements Windows Security; it is not an independent antivirus engine or an always-on traffic filter. It does not intercept browsing, payments, email, or network traffic, block websites, or automatically change Windows protection settings. It does not prevent every attack. Address/text heuristics can miss scams or flag legitimate content. A low-concern result, valid signature, or empty Defender threat list does not establish safety.

Windows status collection works without elevation where Windows policy permits. If Defender is disabled, another provider is active, permissions are restricted, or a system API fails, review the available results and Windows Security. ATGuard does not silently elevate or enable protections.

## Privacy and storage

ATGuard has no account, telemetry, remote reputation lookup, or app-level data upload. Analysis happens locally. Windows Defender and certificate trust checks follow your Windows configuration. Reports can contain device names, network addresses, threat resources, file names, and inspected hostnames; choose where to save or share them.

Preferences and activity live in Electron's per-user application data (`%APPDATA%/ATGuard`, or the product's Electron user-data directory). Turning history persistence off clears its saved copy; current-session events remain visible until the app closes. The app closes completely when its window is closed; there is no background service or start-at-login registration.

## Development

Requires Windows 10/11 and Node.js 24 or newer for development. The packaged executable includes its runtime.

```powershell
npm ci
npm run desktop:dev
```

The local browser preview is available with `npm run dev`. It supports link/message analysis and visibly marks device features as desktop-only.

```powershell
npm test
npm run build
node scripts/desktop-smoke.mjs
npm run package
node scripts/desktop-smoke.mjs --packaged
```

`scripts/desktop-smoke.mjs` uses a fresh temporary profile, reads real Windows status, verifies the renderer sandbox, and checks core navigation and analysis flows. It never starts a Defender scan or changes Windows settings. File hashing and signature behavior are tested separately. Generated app screenshots are in `artifacts/`.

Electron's renderer is sandboxed, context-isolated, and has no Node access. The preload exposes narrow IPC functions; main-process handlers verify the caller. PowerShell operations use fixed scripts and `execFile` with bounded execution. A file path enters the signature script through an environment variable and `-LiteralPath`, rather than command interpolation. External navigation, popups, webviews, and browser permission requests are blocked.

## Technical references

- [Electron security guidance](https://www.electronjs.org/docs/latest/tutorial/security)
- [Microsoft Defender PowerShell module](https://learn.microsoft.com/en-us/powershell/module/defender/)
- [Windows Firewall profiles](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [Windows Authenticode signatures](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
- [Microsoft phishing guidance](https://support.microsoft.com/en-gb/security/protect-yourself-from-phishing)
