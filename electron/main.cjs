const { app, BrowserWindow, ipcMain, dialog, shell, session, clipboard } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const fs = require('node:fs/promises');
const windows = require('./windows.cjs');

let mainWindow;
let scanRunning = false;
const isDev = !app.isPackaged && process.argv.includes('--dev');
const appPage = pathToFileURL(path.join(__dirname, '../dist/index.html')).href;

function trusted(event) {
  const url = event.senderFrame?.url;
  return event.sender === mainWindow?.webContents && event.senderFrame === event.sender.mainFrame &&
    (isDev ? url === 'http://127.0.0.1:5173/' : url === appPage);
}
function handle(channel, fn) {
  ipcMain.handle(channel, async (event, ...args) => {
    if (!trusted(event)) throw new Error('Request origin rejected.');
    return fn(...args);
  });
}
function registerHandlers() {
  handle('system:status', windows.getSystemStatus);
  handle('system:connections', windows.getConnections);
  handle('file:copy-fingerprint', (hash) => {
    if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/i.test(hash)) throw new Error('Invalid SHA-256 fingerprint.');
    clipboard.writeText(hash);
    return { copied: true };
  });
  handle('system:scan', async () => {
    if (scanRunning) return { ok: false, message: 'A Defender scan request is already running.' };
    scanRunning = true;
    try { return await windows.runDefenderScan(); }
    finally { scanRunning = false; }
  });
  handle('file:inspect', async () => {
    const selected = await dialog.showOpenDialog(mainWindow, { title: 'Inspect a file with ATGuard', properties: ['openFile'] });
    if (selected.canceled || !selected.filePaths[0]) return null;
    return windows.inspectFile(selected.filePaths[0]);
  });
  handle('system:open-security', async () => {
    if (process.platform !== 'win32') return { ok: false, message: 'Windows Security is available on Windows.' };
    await shell.openExternal('windowsdefender:');
    return { ok: true };
  });
  handle('report:export', async (report) => {
    if (!report || typeof report !== 'object' || Array.isArray(report)) throw new Error('Invalid report.');
    const serialized = JSON.stringify(report, null, 2);
    if (serialized.length > 2_000_000) throw new Error('Report exceeds the size limit.');
    const selected = await dialog.showSaveDialog(mainWindow, {
      title: 'Export ATGuard report', defaultPath: `ATGuard-report-${new Date().toISOString().slice(0, 10)}.json`,
      filters: [{ name: 'JSON report', extensions: ['json'] }],
    });
    if (selected.canceled || !selected.filePath) return { saved: false };
    await fs.writeFile(selected.filePath, serialized, 'utf8');
    return { saved: true, path: selected.filePath };
  });
  for (const [channel, action] of Object.entries({
    'window:minimize': () => mainWindow.minimize(),
    'window:maximize': () => mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize(),
    'window:close': () => mainWindow.close(),
  })) ipcMain.on(channel, (event) => { if (trusted(event)) action(); });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440, height: 960, minWidth: 1000, minHeight: 720, title: 'ATGuard',
    backgroundColor: '#0b0d0c', frame: false, show: false,
    icon: path.join(__dirname, '../assets/icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, devTools: !app.isPackaged },
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', event => event.preventDefault());
  mainWindow.webContents.on('will-attach-webview', event => event.preventDefault());
  mainWindow.once('ready-to-show', () => mainWindow.show());
  if (isDev) mainWindow.loadURL('http://127.0.0.1:5173/');
  else mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.show(); mainWindow.focus(); } });
  app.whenReady().then(() => {
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    registerHandlers(); createWindow();
  });
  app.on('window-all-closed', () => app.quit());
}
