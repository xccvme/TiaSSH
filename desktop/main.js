const { app, BrowserWindow, Menu, shell, ipcMain, clipboard } = require('electron');
const path = require('path');
const { Client } = require('ssh2');
const { CHANNELS, createTransport } = require('./transport');

// Single instance
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.quit();

function wireNativeTransport(win) {
  const appEntryUrl = new URL('file://' + path.join(__dirname, 'web', 'index.html')).href;
  const transport = createTransport({
    pinStorePath: path.join(app.getPath('userData'), 'ssh-host-pins.json'),
    createClient: () => new Client(),
    send: payload => {
      if (!win.isDestroyed()) win.webContents.send('native-transport:event', payload);
    }
  });

  const isTrustedRendererCall = event => {
    const frame = event.senderFrame;
    return event.sender === win.webContents && frame === win.webContents.mainFrame && (!frame || !frame.url || frame.url === appEntryUrl);
  };

  const handler = (event, message) => {
    if (!isTrustedRendererCall(event)) return;
    if (!message || typeof message !== 'object' || !CHANNELS.includes(message.type)) return;
    try { transport.handle(message); }
    catch (error) {
      const tag = message && message.data && typeof message.data._tag === 'string' ? message.data._tag : '';
      const type = String(message.type || '').startsWith('sftp-') ? 'sftp-error' : 'ssh-error';
      if (tag) win.webContents.send('native-transport:event', { type, data: { _tag: tag, error: String(error.message || error) } });
    }
  };

  const closeAllHandler = event => {
    if (!isTrustedRendererCall(event)) return;
    transport.dispose();
  };

  let disposed = false;
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    ipcMain.removeListener('native-transport:send', handler);
    ipcMain.removeListener('native-transport:close-all', closeAllHandler);
    transport.dispose();
  };

  ipcMain.on('native-transport:send', handler);
  ipcMain.on('native-transport:close-all', closeAllHandler);
  win.on('closed', dispose);
  app.once('before-quit', dispose);
  win.webContents.on('did-start-navigation', (_event, _url, isInPlace, isMainFrame) => {
    if (!isInPlace && isMainFrame) transport.dispose();
  });
  win.webContents.on('will-navigate', event => event.preventDefault());
}

// Clipboard untuk renderer (dipanggil sekali). Hanya frame utama aplikasi sendiri yang dilayani.
function wireClipboard() {
  if (!ipcMain || typeof ipcMain.handle !== 'function' || !clipboard) return;
  const appEntryUrl = new URL('file://' + path.join(__dirname, 'web', 'index.html')).href;
  const trusted = event => {
    const frame = event.senderFrame;
    const win = BrowserWindow.fromWebContents ? BrowserWindow.fromWebContents(event.sender) : null;
    return !!win && frame === event.sender.mainFrame && (!frame || !frame.url || frame.url === appEntryUrl);
  };
  ipcMain.handle('clipboard:read', event => trusted(event) ? clipboard.readText() : '');
  ipcMain.handle('clipboard:write', (event, text) => {
    if (!trusted(event) || typeof text !== 'string' || text.length > 10 * 1024 * 1024) return false;
    clipboard.writeText(text);
    return true;
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 780,
    minWidth: 760,
    minHeight: 480,
    title: 'TiaSSH',
    backgroundColor: '#0f1117',
    autoHideMenuBar: true,
    icon: path.join(__dirname, 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.loadFile(path.join(__dirname, 'web', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http')) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.on('page-title-updated', e => e.preventDefault());
  wireNativeTransport(win);
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  wireClipboard();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('second-instance', () => {
  const [w] = BrowserWindow.getAllWindows();
  if (w) { if (w.isMinimized()) w.restore(); w.focus(); }
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
