/**
 * Electron main process — Camera Discovery Octopus
 *
 * Spawns the Flask backend, waits for it to be ready,
 * then opens the BrowserWindow pointed at localhost.
 */

const { app, BrowserWindow, ipcMain, Menu, dialog } = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const net = require('net');
const os = require('os');

// ─── Config ──────────────────────────────────────────────────────────────
const FLASK_PORT = 5000;
const FLASK_HOST = '127.0.0.1';
const FLASK_STARTUP_TIMEOUT = 30000; // 30s max wait for Flask
const WINDOW_WIDTH = 1400;
const WINDOW_HEIGHT = 900;
const IS_DEV = process.argv.includes('--dev');

let mainWindow = null;
let flaskProcess = null;

// ─── Flask backend ───────────────────────────────────────────────────────

function getPythonPath() {
  // In packaged app, use bundled Python or system Python
  if (app.isPackaged) {
    // Look for python in PATH, prefer python3
    return 'python';
  }
  return 'python';
}

function getFlaskModule() {
  if (app.isPackaged) {
    // In packaged app, the camdiscover module is in extraResources
    return 'camdiscover.webapp';
  }
  return 'camdiscover.webapp';
}

function startFlask() {
  return new Promise((resolve, reject) => {
    const pythonPath = getPythonPath();
    const modulePath = getFlaskModule();

    // We run: python -m camdiscover web --port 5000
    const args = ['-m', 'camdiscover', 'web', '--host', FLASK_HOST, '--port', String(FLASK_PORT)];

    console.log(`[Electron] Starting Flask: ${pythonPath} ${args.join(' ')}`);

    flaskProcess = spawn(pythonPath, args, {
      cwd: app.isPackaged ? path.dirname(app.getPath('exe')) : app.getAppPath(),
      env: { ...process.env },
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: true,
    });

    flaskProcess.stdout.on('data', (data) => {
      const msg = data.toString().trim();
      console.log(`[Flask stdout] ${msg}`);
    });

    flaskProcess.stderr.on('data', (data) => {
      const msg = data.toString().trim();
      console.log(`[Flask stderr] ${msg}`);
    });

    flaskProcess.on('error', (err) => {
      console.error(`[Flask] Failed to start: ${err.message}`);
      reject(err);
    });

    flaskProcess.on('close', (code) => {
      console.log(`[Flask] Process exited with code ${code}`);
      flaskProcess = null;
    });

    // Wait for Flask to be ready by polling the port
    waitForFlask(FLASK_HOST, FLASK_PORT, FLASK_STARTUP_TIMEOUT)
      .then(() => resolve())
      .catch((err) => reject(err));
  });
}

function waitForFlask(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    function tryConnect() {
      const socket = new net.Socket();
      socket.setTimeout(1000);

      socket.on('connect', () => {
        socket.destroy();
        console.log(`[Electron] Flask is ready on ${host}:${port}`);
        resolve();
      });

      socket.on('error', () => {
        socket.destroy();
        if (Date.now() - startTime > timeout) {
          reject(new Error(`Flask did not start within ${timeout / 1000}s`));
        } else {
          setTimeout(tryConnect, 500);
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        if (Date.now() - startTime > timeout) {
          reject(new Error(`Flask did not start within ${timeout / 1000}s`));
        } else {
          setTimeout(tryConnect, 500);
        }
      });

      socket.connect(port, host);
    }

    // Give Flask a moment before first check
    setTimeout(tryConnect, 1000);
  });
}

function stopFlask() {
  if (flaskProcess) {
    console.log('[Electron] Stopping Flask...');
    // On Windows, we need to kill the process tree
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', String(flaskProcess.pid), '/f', '/t'], { shell: true });
    } else {
      flaskProcess.kill('SIGTERM');
    }
    flaskProcess = null;
  }
}

// ─── Window ──────────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width: WINDOW_WIDTH,
    height: WINDOW_HEIGHT,
    minWidth: 1024,
    minHeight: 680,
    title: 'Camera Discovery Octopus',
    backgroundColor: '#08090d',
    icon: path.join(__dirname, 'icons', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
    },
    // Frameless for custom title bar (matches the dark ops theme)
    frame: false,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0c0e14',
      symbolColor: '#8b95a5',
      height: 38,
    },
  });

  // Load the Flask app
  mainWindow.loadURL(`http://${FLASK_HOST}:${FLASK_PORT}`);

  if (IS_DEV) {
    mainWindow.webContents.openDevTools({ mode: 'bottom' });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Build application menu
  const menuTemplate = [
    {
      label: 'File',
      submenu: [
        { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: () => mainWindow.reload() },
        { type: 'separator' },
        { label: 'Quit', accelerator: 'CmdOrCtrl+Q', click: () => app.quit() },
      ],
    },
    {
      label: 'View',
      submenu: [
        { label: 'Toggle DevTools', accelerator: 'F12', click: () => mainWindow.webContents.toggleDevTools() },
        { type: 'separator' },
        { label: 'Zoom In', accelerator: 'CmdOrCtrl+Plus', click: () => mainWindow.webContents.setZoomLevel(mainWindow.webContents.getZoomLevel() + 0.5) },
        { label: 'Zoom Out', accelerator: 'CmdOrCtrl+-', click: () => mainWindow.webContents.setZoomLevel(mainWindow.webContents.getZoomLevel() - 0.5) },
        { label: 'Reset Zoom', accelerator: 'CmdOrCtrl+0', click: () => mainWindow.webContents.setZoomLevel(0) },
      ],
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About Camera Discovery Octopus',
          click: () => {
            const { dialog } = require('electron');
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About',
              message: 'Camera Discovery Octopus',
              detail: 'Vendor-agnostic IP camera discovery tool\nv1.0.0\n\nPassive sniffer + DHCP catcher + ONVIF finder\n+ RTSP/web scanner + MAC/vendor identifier\n+ subnet mapper + DPI protocol validation',
            });
          },
        },
      ],
    },
  ];

  const menu = Menu.buildFromTemplate(menuTemplate);
  Menu.setApplicationMenu(menu);
}

// ─── IPC handlers ────────────────────────────────────────────────────────

ipcMain.handle('app:minimize', () => mainWindow?.minimize());
ipcMain.handle('app:maximize', () => {
  if (mainWindow?.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow?.maximize();
  }
});
ipcMain.handle('app:close', () => mainWindow?.close());
ipcMain.handle('app:isMaximized', () => mainWindow?.isMaximized());
ipcMain.handle('app:getFlaskUrl', () => `http://${FLASK_HOST}:${FLASK_PORT}`);
ipcMain.handle('app:restartFlask', async () => {
  stopFlask();
  try {
    await startFlask();
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

// ─── Admin elevation (Windows) ──────────────────────────────────────────

function isRunningAsAdmin() {
  if (process.platform !== 'win32') return true;
  try {
    // Check if current token is in the Administrators group (S-1-5-32-544)
    const out = execSync('whoami /groups /fo csv', { encoding: 'utf8', stdio: ['pipe','pipe','pipe'] });
    return out.includes('S-1-5-32-544');
  } catch {
    return false;
  }
}

function relaunchAsAdmin() {
  // Use the absolute app path so the elevated process finds the right directory
  const exePath = process.execPath;
  const appPath = app.getAppPath();
  try {
    spawn('powershell.exe', [
      '-Command',
      `Start-Process -FilePath "${exePath}" -ArgumentList '"${appPath}"' -Verb RunAs -WorkingDirectory "${appPath}"`
    ], { detached: true, stdio: 'ignore' });
  } catch (e) {
    console.error('[Electron] Failed to relaunch as admin:', e.message);
  }
  app.quit();
}

// ─── App lifecycle ───────────────────────────────────────────────────────

app.whenReady().then(async () => {
  // On Windows, require admin for raw socket capture and netsh commands
  if (process.platform === 'win32' && !isRunningAsAdmin()) {
    const choice = dialog.showMessageBoxSync({
      type: 'warning',
      title: 'Administrator Required',
      message: 'Camera Discovery Octopus needs administrator privileges for:\n• Raw packet capture (subnet detection)\n• netsh interface IP management\n• ONVIF multicast on all subnets',
      buttons: ['Relaunch as Admin', 'Continue Anyway'],
      defaultId: 0,
      cancelId: 1,
    });
    if (choice === 0) {
      relaunchAsAdmin();
      return;
    }
  }

  try {
    console.log('[Electron] Starting Flask backend...');
    await startFlask();
    console.log('[Electron] Creating window...');
    createWindow();
  } catch (err) {
    console.error(`[Electron] Failed to start: ${err.message}`);
    dialog.showErrorBox(
      'Failed to Start Backend',
      `Could not start the Python/Flask backend.\n\nError: ${err.message}\n\nMake sure Python is installed and the camdiscover module is available.\nRun: pip install -e .`
    );
    app.quit();
  }
});

app.on('window-all-closed', () => {
  stopFlask();
  app.quit();
});

app.on('before-quit', () => {
  stopFlask();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Handle single instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });
}
