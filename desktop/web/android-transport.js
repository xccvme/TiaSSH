(function () {
  const cap = window.Capacitor;
  if (!cap || typeof cap.getPlatform !== 'function' || cap.getPlatform() !== 'android') {
    return;
  }

  let plugin;
  try {
    if (typeof cap.registerPlugin === 'function') {
      plugin = cap.registerPlugin('SshTransport');
    } else if (cap.Plugins && cap.Plugins.SshTransport) {
      plugin = cap.Plugins.SshTransport;
    }
  } catch (e) {}
  if (!plugin) return;

  let listenerReady = null;
  let generation = 0;

  function ensureListener() {
    if (listenerReady) return listenerReady;
    const result = plugin.addListener('transportEvent', (event) => {
      handlers.forEach((fn) => {
        try { fn(event); } catch (_) {}
      });
    });
    
    // Handle both Promise (registerPlugin) and sync handle (Plugins API)
    if (result && typeof result.then === 'function') {
      listenerReady = result.catch((err) => {
        listenerReady = null;
        throw err;
      });
    } else {
      listenerReady = Promise.resolve(result);
    }
    return listenerReady;
  }

  function methodFor(type) {
    if (type === 'ssh-open' || type === 'sftp-open') return 'open';
    if (type === 'ssh-close' || type === 'sftp-close') return 'close';
    return 'send';
  }

  const handlers = new Set();

  window.tiasshNativeTransport = {
    available: true,
    async send(message) {
      if (!message || typeof message !== 'object' || typeof message.type !== 'string') {
        throw new Error('invalid transport message');
      }
      const g = generation;
      await ensureListener();
      if (g !== generation) throw new Error('transport closed');
      const method = methodFor(message.type);
      if (typeof plugin[method] !== 'function') throw new Error('transport method unavailable');
      return plugin[method](message);
    },
    onEvent(handler) {
      if (typeof handler !== 'function') throw new Error('handler must be function');
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
    closeAll() {
      generation += 1;
      if (typeof plugin.closeAll === 'function') return plugin.closeAll();
      return Promise.resolve();
    }
  };
})();
