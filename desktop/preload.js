'use strict';

const { contextBridge, ipcRenderer } = require('electron');
const allowedSend = new Set(['ssh-open', 'ssh-input', 'ssh-resize', 'ssh-close', 'sftp-open', 'sftp-op', 'sftp-close']);
const sendChannel = 'native-transport:send';
const closeAllChannel = 'native-transport:close-all';
const eventChannel = 'native-transport:event';

contextBridge.exposeInMainWorld('tiasshNativeTransport', {
  available: true,
  send(message) {
    if (!message || typeof message !== 'object') throw new Error('message object required');
    if (!allowedSend.has(message.type)) throw new Error('unsupported channel');
    if (!message.data || typeof message.data._tag !== 'string' || !message.data._tag) throw new Error('missing _tag');
    ipcRenderer.send(sendChannel, message);
    return Promise.resolve();
  },
  closeAll() {
    ipcRenderer.send(closeAllChannel);
    return Promise.resolve();
  },
  onEvent(handler) {
    if (typeof handler !== 'function') throw new Error('handler must be a function');
    const listener = (_event, payload) => handler(payload);
    ipcRenderer.on(eventChannel, listener);
    return () => ipcRenderer.removeListener(eventChannel, listener);
  }
});
