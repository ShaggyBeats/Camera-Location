/**
 * Preload script — Camera Discovery Octopus
 * Exposes safe IPC bridge for desktop features.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // Window controls
  minimize: () => ipcRenderer.invoke('app:minimize'),
  maximize: () => ipcRenderer.invoke('app:maximize'),
  close: () => ipcRenderer.invoke('app:close'),
  isMaximized: () => ipcRenderer.invoke('app:isMaximized'),

  // Flask backend
  getFlaskUrl: () => ipcRenderer.invoke('app:getFlaskUrl'),
  restartFlask: () => ipcRenderer.invoke('app:restartFlask'),

  // Platform info
  platform: process.platform,
  isElectron: true,
});
