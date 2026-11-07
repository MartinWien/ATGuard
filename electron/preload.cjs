const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('atguard', Object.freeze({
  getSystemStatus: () => ipcRenderer.invoke('system:status'),
  getConnections: () => ipcRenderer.invoke('system:connections'),
  runDefenderScan: () => ipcRenderer.invoke('system:scan'),
  inspectFile: () => ipcRenderer.invoke('file:inspect'),
  copyFingerprint: (hash) => ipcRenderer.invoke('file:copy-fingerprint', hash),
  openSecurity: () => ipcRenderer.invoke('system:open-security'),
  exportReport: (report) => ipcRenderer.invoke('report:export', report),
  minimize: () => ipcRenderer.send('window:minimize'),
  maximize: () => ipcRenderer.send('window:maximize'),
  close: () => ipcRenderer.send('window:close'),
}));
