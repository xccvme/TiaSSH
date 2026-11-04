package com.tiassh.app;

import android.util.Base64;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.ChannelShell;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpATTRS;
import com.jcraft.jsch.SftpException;
import com.jcraft.jsch.UserInfo;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@CapacitorPlugin(name = "SshTransport")
public class SshTransportPlugin extends Plugin {

    private static final int SSH_CONNECT_TIMEOUT_MS = 15000;
    private static final int MAX_TAG_LEN = 256;
    private static final int MAX_PATH_LEN = 4096;
    private static final int MAX_SSH_INPUT_BYTES = 256 * 1024;
    private static final int MAX_SFTP_WRITE_BYTES = 2 * 1024 * 1024;
    private static final long MAX_SFTP_READ_WINDOW = 128L * 1024L * 1024L;

    private final ExecutorService ioExecutor = Executors.newCachedThreadPool();
    private final ExecutorService commandExecutor = Executors.newSingleThreadExecutor();
    private final Map<String, SshConn> sshConns = new ConcurrentHashMap<>();
    private final Map<String, SftpConn> sftpConns = new ConcurrentHashMap<>();
    private final Map<String, Session> pendingSessions = new ConcurrentHashMap<>();
    private final Object lifecycleLock = new Object();

    private volatile long generation = 1L;
    private volatile boolean destroyed = false;

    @PluginMethod
    public void open(PluginCall call) {
        JSObject message = call.getData();
        String type = message.getString("type", "");
        JSObject data = message.getJSObject("data");
        if (data == null) {
            call.reject("missing data");
            return;
        }
        String tag;
        try {
            tag = requireTag(data);
        } catch (Exception e) {
            call.reject(safeMessage(e));
            return;
        }
        WorkCtx work = beginWork(tag);
        if (work == null) {
            call.reject("transport closed");
            return;
        }
        call.resolve();
        commandExecutor.execute(() -> {
            if (!isCurrent(work)) return;
            if ("ssh-open".equals(type)) {
                openSsh(work, tag, data);
                return;
            }
            if ("sftp-open".equals(type)) {
                openSftp(work, tag, data);
                return;
            }
            emitError(work, type != null && type.startsWith("sftp") ? "sftp-error" : "ssh-error", tag, "unsupported open type");
        });
    }

    @PluginMethod
    public void send(PluginCall call) {
        JSObject message = call.getData();
        String type = message.getString("type", "");
        JSObject data = message.getJSObject("data");
        if (data == null) {
            call.reject("missing data");
            return;
        }
        String tag;
        try {
            tag = requireTag(data);
        } catch (Exception e) {
            call.reject(safeMessage(e));
            return;
        }
        WorkCtx work = beginWork(tag);
        if (work == null) {
            call.reject("transport closed");
            return;
        }
        call.resolve();
        commandExecutor.execute(() -> handleSend(work, type, tag, data));
    }

    @PluginMethod
    public void close(PluginCall call) {
        JSObject message = call.getData();
        JSObject data = message.has("data") ? message.getJSObject("data") : new JSObject();
        if (data == null) {
            call.reject("missing data");
            return;
        }
        String tag;
        try {
            tag = requireTag(data);
        } catch (Exception e) {
            call.reject(safeMessage(e));
            return;
        }
        WorkCtx work = beginWork(tag);
        if (work == null) {
            call.resolve();
            return;
        }
        commandExecutor.execute(() -> {
            if (isCurrent(work)) closeTag(tag);
            call.resolve();
        });
    }

    @PluginMethod
    public void closeAll(PluginCall call) {
        closeAllInternal(true);
        call.resolve();
    }

    @Override
    protected void handleOnDestroy() {
        synchronized (lifecycleLock) {
            destroyed = true;
            generation++;
        }
        closeAllInternal(false);
        commandExecutor.shutdownNow();
        ioExecutor.shutdownNow();
        super.handleOnDestroy();
    }

    private void handleSend(WorkCtx work, String type, String tag, JSObject data) {
        if (!isCurrent(work)) return;
        try {
            if ("ssh-input".equals(type)) {
                SshConn conn = sshConns.get(tag);
                if (conn == null || conn.generation != work.generation || !conn.active) return;
                byte[] payload = decodeBase64(data.getString("data", ""), MAX_SSH_INPUT_BYTES, "invalid ssh payload");
                conn.stdin.write(payload);
                conn.stdin.flush();
                return;
            }
            if ("ssh-resize".equals(type)) {
                SshConn conn = sshConns.get(tag);
                if (conn == null || conn.generation != work.generation || !conn.active) return;
                int cols = Math.max(2, data.getInteger("cols", 80));
                int rows = Math.max(2, data.getInteger("rows", 24));
                conn.shell.setPtySize(cols, rows, 0, 0);
                return;
            }
            if ("sftp-op".equals(type)) {
                SftpConn conn = sftpConns.get(tag);
                if (conn == null || conn.sftp == null || conn.generation != work.generation || !conn.active) return;
                handleSftpOp(work, tag, conn.sftp, data);
                return;
            }
            if ("ssh-close".equals(type) || "sftp-close".equals(type)) {
                closeTag(tag);
                return;
            }
            emitError(work, type != null && type.startsWith("sftp") ? "sftp-error" : "ssh-error", tag, "unsupported send type");
        } catch (Exception e) {
            emitError(work, type != null && type.startsWith("sftp") ? "sftp-error" : "ssh-error", tag, safeMessage(e));
        }
    }

    private void openSsh(WorkCtx work, String tag, JSObject data) {
        Session session = null;
        try {
            closeTag(tag);
            session = createSession(data);
            registerPending(work, tag, session);
            requireCurrent(work);
            session.connect(SSH_CONNECT_TIMEOUT_MS);
            requireCurrent(work);

            ChannelShell shell = (ChannelShell) session.openChannel("shell");
            int cols = Math.max(2, data.getInteger("cols", 80));
            int rows = Math.max(2, data.getInteger("rows", 24));
            shell.setPtyType("xterm-256color");
            shell.setPtySize(cols, rows, 0, 0);
            InputStream stdout = shell.getInputStream();
            InputStream stderr = shell.getExtInputStream();
            OutputStream stdin = shell.getOutputStream();
            shell.connect(SSH_CONNECT_TIMEOUT_MS);
            requireCurrent(work);

            SshConn conn = new SshConn(session, shell, stdin, work.generation);
            SshConn prior = sshConns.put(tag, conn);
            if (prior != null) prior.close();
            clearPending(tag, session);
            emit(work, tag, "ssh-ready", new JSObject());
            startSshPump(work, tag, conn, stdout, true);
            startSshPump(work, tag, conn, stderr, false);
        } catch (StaleWorkException ignored) {
            clearPending(tag, session);
            if (session != null) {
                try { session.disconnect(); } catch (Exception ignored2) {}
            }
        } catch (Exception e) {
            clearPending(tag, session);
            if (session != null) {
                try { session.disconnect(); } catch (Exception ignored) {}
            }
            if (isCurrent(work)) {
                emitError(work, "ssh-error", tag, safeMessage(e));
                closeTag(tag);
            }
        }
    }

    private void startSshPump(WorkCtx work, String tag, SshConn conn, InputStream source, boolean terminateOnEof) {
        ioExecutor.execute(() -> {
            byte[] buf = new byte[4096];
            try {
                int n;
                while (conn.active && source != null && isCurrent(work) && (n = source.read(buf)) >= 0) {
                    if (n == 0) continue;
                    String b64 = Base64.encodeToString(copyOf(buf, n), Base64.NO_WRAP);
                    JSObject data = new JSObject();
                    data.put("data", b64);
                    emit(work, tag, "ssh-data", data);
                }
            } catch (IOException ignored) {
            } finally {
                if (terminateOnEof && conn.active && isCurrent(work) && !commandExecutor.isShutdown()) {
                    commandExecutor.execute(() -> {
                        if (!isCurrent(work)) return;
                        if (sshConns.get(tag) == conn) {
                            closeTag(tag);
                            JSObject term = new JSObject();
                            term.put("reason", "connection closed");
                            emit(work, tag, "ssh-terminated", term);
                        }
                    });
                }
            }
        });
    }

    private void openSftp(WorkCtx work, String tag, JSObject data) {
        Session session = null;
        try {
            closeTag(tag);
            session = createSession(data);
            registerPending(work, tag, session);
            requireCurrent(work);
            session.connect(SSH_CONNECT_TIMEOUT_MS);
            requireCurrent(work);

            ChannelSftp sftp = (ChannelSftp) session.openChannel("sftp");
            sftp.connect(SSH_CONNECT_TIMEOUT_MS);
            requireCurrent(work);

            SftpConn conn = new SftpConn(session, sftp, work.generation);
            SftpConn prior = sftpConns.put(tag, conn);
            if (prior != null) prior.close();
            clearPending(tag, session);
            JSObject out = new JSObject();
            out.put("cwd", "");
            emit(work, tag, "sftp-ready", out);
        } catch (StaleWorkException ignored) {
            clearPending(tag, session);
            if (session != null) {
                try { session.disconnect(); } catch (Exception ignored2) {}
            }
        } catch (Exception e) {
            clearPending(tag, session);
            if (session != null) {
                try { session.disconnect(); } catch (Exception ignored) {}
            }
            if (isCurrent(work)) {
                emitError(work, "sftp-error", tag, safeMessage(e));
                closeTag(tag);
            }
        }
    }

    private void handleSftpOp(WorkCtx work, String tag, ChannelSftp sftp, JSObject data) {
        String op = data.getString("op", "").trim();
        if (op.isEmpty()) {
            emitError(work, "sftp-error", tag, "op required");
            return;
        }
        String path = safePath(data.getString("path", "/"));
        try {
            if ("list".equals(op)) {
                Vector<ChannelSftp.LsEntry> entries = sftp.ls(path);
                JSArray files = new JSArray();
                for (ChannelSftp.LsEntry entry : entries) {
                    String name = entry.getFilename();
                    if (".".equals(name) || "..".equals(name)) continue;
                    SftpATTRS attrs = entry.getAttrs();
                    JSObject item = new JSObject();
                    item.put("name", name);
                    item.put("size", attrs == null ? 0 : attrs.getSize());
                    item.put("time", attrs == null ? 0 : attrs.getMTime() * 1000L);
                    item.put("isDir", attrs != null && attrs.isDir());
                    files.put(item);
                }
                JSObject out = new JSObject();
                out.put("path", path);
                out.put("files", files);
                emit(work, tag, "sftp-list", out);
                return;
            }
            if ("mkdir".equals(op)) {
                sftp.mkdir(path);
                emitOk(work, tag, path, 0);
                return;
            }
            if ("rmdir".equals(op)) {
                sftp.rmdir(path);
                emitOk(work, tag, path, 0);
                return;
            }
            if ("unlink".equals(op)) {
                sftp.rm(path);
                emitOk(work, tag, path, 0);
                return;
            }
            if ("rename".equals(op)) {
                String to = safePath(data.getString("to", ""));
                if (to.isEmpty()) throw new IllegalArgumentException("rename target required");
                sftp.rename(path, to);
                JSObject out = new JSObject();
                out.put("path", path);
                out.put("to", to);
                emit(work, tag, "sftp-ok", out);
                return;
            }
            if ("read".equals(op)) {
                long start = asLong(data, "start", 0L);
                long end = asLong(data, "end", Long.MAX_VALUE);
                if (start < 0 || end <= start) throw new IllegalArgumentException("invalid read range");
                if (end - start > MAX_SFTP_READ_WINDOW) throw new IllegalArgumentException("read range too large");
                try (InputStream in = sftp.get(path)) {
                    skipFully(in, start);
                    byte[] buf = new byte[64 * 1024];
                    long remaining = end - start;
                    while (remaining > 0 && isCurrent(work)) {
                        int want = (int) Math.min(buf.length, remaining);
                        int n = in.read(buf, 0, want);
                        if (n <= 0) break;
                        remaining -= n;
                        JSObject chunk = new JSObject();
                        chunk.put("path", path);
                        chunk.put("data", Base64.encodeToString(copyOf(buf, n), Base64.NO_WRAP));
                        emit(work, tag, "sftp-data", chunk);
                    }
                }
                JSObject done = new JSObject();
                done.put("path", path);
                emit(work, tag, "sftp-end", done);
                return;
            }
            if ("write".equals(op)) {
                byte[] bytes = decodeBase64(data.getString("data", ""), MAX_SFTP_WRITE_BYTES, "invalid sftp payload");
                boolean append = Boolean.TRUE.equals(data.getBoolean("append", false));
                long start = asLong(data, "start", 0L);
                if (start < 0) throw new IllegalArgumentException("invalid write offset");
                try (ByteArrayInputStream in = new ByteArrayInputStream(bytes)) {
                    if (append) {
                        sftp.put(in, path, ChannelSftp.APPEND);
                    } else if (start > 0) {
                        long existingSize = sftp.lstat(path).getSize();
                        if (start < existingSize) throw new IllegalArgumentException("write offset behind EOF");
                        long resumeDelta = start - existingSize;
                        try (OutputStream out = sftp.put(path, null, ChannelSftp.RESUME, resumeDelta)) {
                            out.write(bytes);
                        }
                    } else {
                        sftp.put(in, path, ChannelSftp.OVERWRITE);
                    }
                }
                emitOk(work, tag, path, bytes.length);
                return;
            }
            if ("stat".equals(op)) {
                SftpATTRS attrs = sftp.lstat(path);
                JSObject out = new JSObject();
                out.put("path", path);
                out.put("size", attrs.getSize());
                out.put("mtime", attrs.getMTime() * 1000L);
                out.put("isDir", attrs.isDir());
                emit(work, tag, "sftp-stat", out);
                return;
            }
            emitError(work, "sftp-error", tag, "unknown op: " + op);
        } catch (SftpException e) {
            emitError(work, "sftp-error", tag, safeMessage(e));
        } catch (Exception e) {
            emitError(work, "sftp-error", tag, safeMessage(e));
        }
    }

    private Session createSession(JSObject data) throws Exception {
        String host = data.getString("host", "").trim();
        String username = data.getString("username", "").trim();
        int port = data.getInteger("port", 22);
        if (port < 1 || port > 65535) throw new IllegalArgumentException("invalid SSH port");
        if (host.isEmpty() || username.isEmpty()) throw new IllegalArgumentException("host+username required");

        String password = data.getString("password", "");
        String privateKey = data.getString("privateKey", "");
        String keyPass = data.getString("keyPass", "");
        if (password.isEmpty() && privateKey.isEmpty()) throw new IllegalArgumentException("password or privateKey required");

        JSch jsch = new JSch();
        // Trust on first use; subsequent connections must match the pinned key.
        final android.content.SharedPreferences pins = getContext().getSharedPreferences("ssh-host-keys", 0);
        jsch.setHostKeyRepository(new HostKeyRepository() {
            public int check(String endpoint, byte[] key) {
                String encoded = Base64.encodeToString(key, Base64.NO_WRAP);
                String existing = pins.getString(endpoint, null);
                if (existing == null) return pins.edit().putString(endpoint, encoded).commit() ? OK : CHANGED;
                return existing.equals(encoded) ? OK : CHANGED;
            }
            public void add(HostKey key, UserInfo info) { }
            public void remove(String host, String type) { }
            public void remove(String host, String type, byte[] key) { }
            public String getKnownHostsRepositoryID() { return "Android app-private TOFU pins"; }
            public HostKey[] getHostKey() { return new HostKey[0]; }
            public HostKey[] getHostKey(String host, String type) { return new HostKey[0]; }
        });
        if (!privateKey.isEmpty()) {
            byte[] key = privateKey.getBytes(StandardCharsets.UTF_8);
            byte[] passphrase = keyPass.isEmpty() ? null : keyPass.getBytes(StandardCharsets.UTF_8);
            jsch.addIdentity("inline-key-" + UUID.randomUUID(), key, null, passphrase);
        }

        Session session = jsch.getSession(username, host, port);
        if (!password.isEmpty()) session.setPassword(password);
        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "yes");
        session.setConfig(config);
        session.setServerAliveInterval(10000);
        return session;
    }

    private void emitOk(WorkCtx work, String tag, String path, int bytes) {
        JSObject out = new JSObject();
        out.put("path", path);
        if (bytes > 0) out.put("bytes", bytes);
        emit(work, tag, "sftp-ok", out);
    }

    private void emitError(WorkCtx work, String type, String tag, String error) {
        JSObject out = new JSObject();
        out.put("error", error == null ? "error" : error);
        emit(work, tag, type, out);
    }

    private void emit(WorkCtx work, String tag, String type, JSObject data) {
        if (!isCurrent(work)) return;
        emitRaw(work, tag, type, data);
    }

    private void emitRaw(WorkCtx work, String tag, String type, JSObject data) {
        JSObject payload = new JSObject();
        payload.put("_tag", tag);
        if (data != null) {
            Iterator<String> keys = data.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                payload.put(key, data.opt(key));
            }
        }
        JSObject event = new JSObject();
        event.put("type", type);
        event.put("data", payload);
        if (getActivity() != null) {
            getActivity().runOnUiThread(() -> {
                if (isCurrent(work)) notifyListeners("transportEvent", event);
            });
        }
    }

    private void closeTag(String tag) {
        Session pending = pendingSessions.remove(tag);
        if (pending != null) {
            try { pending.disconnect(); } catch (Exception ignored) {}
        }
        SshConn ssh = sshConns.remove(tag);
        if (ssh != null) ssh.close();
        SftpConn sftp = sftpConns.remove(tag);
        if (sftp != null) sftp.close();
    }

    private void closeAllInternal(boolean incrementGeneration) {
        List<Session> pending;
        List<SshConn> ssh;
        List<SftpConn> sftp;
        synchronized (lifecycleLock) {
            if (incrementGeneration) generation++;
            pending = new ArrayList<>(pendingSessions.values());
            ssh = new ArrayList<>(sshConns.values());
            sftp = new ArrayList<>(sftpConns.values());
            pendingSessions.clear();
            sshConns.clear();
            sftpConns.clear();
        }
        for (Session session : pending) {
            try { session.disconnect(); } catch (Exception ignored) {}
        }
        for (SshConn conn : ssh) conn.close();
        for (SftpConn conn : sftp) conn.close();
    }

    private WorkCtx beginWork(String tag) {
        synchronized (lifecycleLock) {
            if (destroyed) return null;
            return new WorkCtx(generation, tag);
        }
    }

    private boolean isCurrent(WorkCtx work) {
        return work != null && !destroyed && generation == work.generation;
    }

    private void requireCurrent(WorkCtx work) throws StaleWorkException {
        if (!isCurrent(work)) throw new StaleWorkException();
    }

    private void registerPending(WorkCtx work, String tag, Session session) throws StaleWorkException {
        synchronized (lifecycleLock) {
            if (!isCurrent(work)) throw new StaleWorkException();
            pendingSessions.put(tag, session);
        }
    }

    private void clearPending(String tag, Session session) {
        if (tag == null || session == null) return;
        pendingSessions.remove(tag, session);
    }

    private static String requireTag(JSObject data) {
        String tag = data.getString("_tag", "").trim();
        if (tag.isEmpty()) throw new IllegalArgumentException("_tag required");
        if (tag.length() > MAX_TAG_LEN) throw new IllegalArgumentException("_tag too long");
        return tag;
    }

    private static String safeMessage(Exception e) {
        String m = e.getMessage();
        return (m == null || m.trim().isEmpty()) ? e.getClass().getSimpleName() : m;
    }

    private static byte[] copyOf(byte[] src, int n) {
        byte[] out = new byte[n];
        System.arraycopy(src, 0, out, 0, n);
        return out;
    }

    private static long asLong(JSObject data, String key, long defaultValue) {
        if (data == null || !data.has(key)) return defaultValue;
        Object value = data.opt(key);
        if (value instanceof Number) return ((Number) value).longValue();
        if (value instanceof String) {
            try { return Long.parseLong((String) value); }
            catch (Exception ignored) { return defaultValue; }
        }
        return defaultValue;
    }

    private static String safePath(String path) {
        if (path == null || path.isEmpty()) return "/";
        if (path.indexOf('\u0000') >= 0) throw new IllegalArgumentException("invalid path");
        if (path.length() > MAX_PATH_LEN) throw new IllegalArgumentException("path too long");
        return path;
    }

    private static byte[] decodeBase64(String b64, int maxBytes, String invalidMessage) {
        byte[] decoded;
        try {
            decoded = Base64.decode(b64 == null ? "" : b64, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(invalidMessage);
        }
        if (decoded.length > maxBytes) throw new IllegalArgumentException("payload too large");
        return decoded;
    }

    private static void skipFully(InputStream in, long count) throws IOException {
        long remaining = Math.max(0L, count);
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) {
                if (in.read() == -1) break;
                skipped = 1;
            }
            remaining -= skipped;
        }
    }

    private static final class WorkCtx {
        final long generation;
        final String tag;

        WorkCtx(long generation, String tag) {
            this.generation = generation;
            this.tag = tag;
        }
    }

    private static final class StaleWorkException extends Exception { }

    private static final class SshConn {
        final Session session;
        final ChannelShell shell;
        final OutputStream stdin;
        final long generation;
        volatile boolean active = true;

        SshConn(Session session, ChannelShell shell, OutputStream stdin, long generation) {
            this.session = session;
            this.shell = shell;
            this.stdin = stdin;
            this.generation = generation;
        }

        void close() {
            active = false;
            try { stdin.close(); } catch (Exception ignored) {}
            try { shell.disconnect(); } catch (Exception ignored) {}
            try { session.disconnect(); } catch (Exception ignored) {}
        }
    }

    private static final class SftpConn {
        final Session session;
        final ChannelSftp sftp;
        final long generation;
        volatile boolean active = true;

        SftpConn(Session session, ChannelSftp sftp, long generation) {
            this.session = session;
            this.sftp = sftp;
            this.generation = generation;
        }

        void close() {
            active = false;
            try { sftp.disconnect(); } catch (Exception ignored) {}
            try { session.disconnect(); } catch (Exception ignored) {}
        }
    }
}
