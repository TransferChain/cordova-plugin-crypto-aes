package com.transferchain.aes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.security.SecureRandom;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.PluginResult;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public final class AES extends CordovaPlugin {
    // RESOURCE REGISTRY: KEEP THESE THREE COLLECTIONS CONSISTENT
    // sessions maps a session ID to its active cipher/file state. owners links that
    // session to its transaction. transactions tracks completed output files that
    // still need rollback protection. Finalization removes a session and its owner
    // entry, but keeps the finished file in transactions until commit.
    //
    // State progression: open -> create -> update* -> finalize/abort -> commit.
    // One transaction can contain multiple sessions. A failure rolls back the owning
    // transaction, including files produced by earlier sessions in that transaction.
    // These maps are accessed through the serialized stream execution path. Do not
    // introduce direct access from a callback on another thread.
    private final Map<String, StreamSession> sessions = new HashMap<>();
    private final Map<String, List<File>> transactions = new HashMap<>();

    // WHY MAPS, IDS AND FINAL REFERENCES
    // String IDs are opaque handles, not native addresses or caller-provided paths.
    // owners links a session to its transaction so an update failure can roll back
    // all related outputs. UUID uniqueness does not authenticate callers.
    // HashMap itself is not thread-safe. Single-drainer confinement protects these
    // maps; final only prevents replacing their references, not mutating entries.
    // New access paths must preserve confinement or introduce explicit coordination.
    private final Map<String, String> owners = new HashMap<>();
    private final ArrayDeque<Runnable> streamJobs = new ArrayDeque<>();

    // SINGLE-CONSUMER FIFO PROTOCOL
    // ArrayDeque stores pending jobs in arrival order. Enqueue and poll use the same
    // Java monitor; unlock/lock provides visibility for queue state. draining admits
    // one consumer, while later callers append work without starting another one.
    // Jobs execute outside the monitor, avoiding a Java lock held through crypto/I/O.
    //
    // Only one drainer touches stream registries at a time. This is not a dedicated
    // thread: the next drain may use a different Cordova worker. It also serializes
    // all stream sessions, not just updates within one session. Lifecycle cleanup
    // must use this same path to avoid closing a cipher while an update uses it.
    private boolean draining;

    // Route all stream state changes through this FIFO to preserve cipher update
    // order and protect session maps. Computation still runs off the UI thread.
    private synchronized void enqueueStream(Runnable job) {
        // Queue bookkeeping is synchronized, but each job executes outside this monitor.
        // Only the first submitter schedules a drainer; later submitters append to FIFO.
        // When the drainer sees an empty queue it clears draining under the same monitor,
        // so a later submitter can safely schedule the next worker. Scheduling failure
        // resets the queue state and propagates to the caller.
        //
        // This serializes all stream sessions in this plugin instance. It is not a
        // per-session parallel executor; do not assume separate IDs run simultaneously.
        streamJobs.add(job);
        if (draining) return;

        draining = true;
        try {
            cordova.getThreadPool().execute(() -> {
                while (true) {
                    Runnable next;

                    synchronized (AES.this) {
                        next = streamJobs.poll();
                        if (next == null) { draining = false; return; }
                    }

                    next.run();
                }
            });
        } catch (RuntimeException error) {
            streamJobs.clear();
            draining = false;
            throw error;
        }
    }

    @Override public void onReset() { clearStreams(); }

    @Override public void onDestroy() { clearStreams(); }

    private void clearStreams() {
        enqueueStream(() -> {
            for (StreamSession session : sessions.values()) session.close();
            sessions.clear();
            owners.clear();
            for (List<File> files : transactions.values()) for (File file : files) file.delete();
            transactions.clear();
        });
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callback) {
        if (action.equals("open") || action.equals("commit") || action.equals("rollback") || action.equals("create") || action.equals("update") || action.equals("finalize") || action.equals("abort")) {
            try {
                enqueueStream(() -> stream(action, args, callback));
            } catch (RuntimeException error) {
                fail(callback, "OPERATION_FAILED", "Unable to schedule the crypto operation.");
            }

            return true;
        }

        if (!(action.equals("encrypt") || action.equals("decrypt"))) return false;

        try {
            cordova.getThreadPool().execute(() -> {
                try {
                    if (args.length() != 6 || !(args.opt(0) instanceof JSONObject)) {
                        throw invalid("Expected one options object.");
                    }

                    callback.sendPluginResult(perform(action, new CordovaArgs(args)));
                } catch (CryptoFailure error) {
                    fail(callback, error.code, error.getMessage());
                } catch (AEADBadTagException error) {
                    fail(callback, "AUTHENTICATION_FAILED", "AES-GCM authentication failed.");
                } catch (OutOfMemoryError error) {
                    fail(callback, "RESOURCE_LIMIT", "Insufficient memory for the crypto operation.");
                } catch (Exception error) {
                    fail(callback, "OPERATION_FAILED", "Native AES operation failed.");
                }
            });
        } catch (RuntimeException error) {
            fail(callback, "OPERATION_FAILED", "Unable to schedule the crypto operation.");
        }

        return true;
    }

    // GCM and standard CTR finish in one call. ctr-with-hmac uses the separate
    // stream path; preserve the existing GCM/CTR binary callback contract.
    static PluginResult perform(String action, CordovaArgs args) throws Exception {
        JSONObject options = args.getJSONObject(0);
        List<byte[]> buffers = new ArrayList<>();

        try {
            String mode = string(options, "mode");

            if (!mode.equals("GCM") && !mode.equals("CTR")) throw invalid("mode must be GCM or CTR.");

            boolean encrypt = action.equals("encrypt");

            if (mode.equals("CTR") && (!args.isNull(4) || !args.isNull(5))) {
                throw invalid("CTR does not support aad or tag.");
            }

            if (encrypt && !args.isNull(5)) throw invalid("encrypt does not accept tag.");

            byte[] key = bytes(args, 1, "key", 16, 32, buffers);

            if (key.length != 16 && key.length != 24 && key.length != 32) {
                throw invalid("key must contain 16, 24 or 32 bytes.");
            }

            byte[] data = bytes(args, 2, "data", 0, 1048576, buffers);

            // GCM uses a 12-byte nonce; CTR uses a full 16-byte counter block. Decryption
            // must receive the original IV. Encryption generates one only when omitted.
            int ivLength = mode.equals("GCM") ? 12 : 16;

            byte[] iv;

            if (encrypt && args.isNull(3)) {
                iv = new byte[ivLength];
                buffers.add(iv);
                new SecureRandom().nextBytes(iv);
            } else {
                iv = bytes(args, 3, "iv", ivLength, ivLength, buffers);
            }

            // ALGORITHM SELECTION AND AUTHENTICATION
            // mode is allowlisted before building the provider transformation. Callers cannot
            // select arbitrary transformation strings. NoPadding fits CTR partial blocks
            // and GCM's authenticated-encryption format; PKCS padding is not needed.
            // GCM verifies its 128-bit tag before plaintext is returned and binds optional AAD.
            // Standard CTR does not authenticate ciphertext, even when decryption succeeds.
            // The separate CTR/HMAC stream adds encrypt-then-MAC with a distinct key input.
            Cipher cipher = Cipher.getInstance("AES/" + mode + "/NoPadding");
            SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
            int operation = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

            byte[] input = data;

            if (mode.equals("GCM")) {
                cipher.init(operation, aesKey, new GCMParameterSpec(128, iv));
                if (!args.isNull(4)) cipher.updateAAD(bytes(args, 4, "aad", 0, 1048576, buffers));
                if (!encrypt) {
                    byte[] tag = bytes(args, 5, "tag", 16, 16, buffers);

                    // javax.crypto expects GCM ciphertext followed by its tag. Our bridge keeps
                    // them separate, so assemble the provider input and register it for wiping.
                    input = Arrays.copyOf(data, data.length + 16);
                    buffers.add(input);
                    System.arraycopy(tag, 0, input, data.length, 16);
                }
            } else {
                checkCounter(iv, data.length);
                cipher.init(operation, aesKey, new IvParameterSpec(iv));
            }

            // GCM authentication is checked by doFinal. Deliver plaintext only after this
            // returns successfully; a bad tag must take the error path without output.
            byte[] output = cipher.doFinal(input);

            buffers.add(output);
            if (!encrypt) return new PluginResult(PluginResult.Status.OK, output);

            List<PluginResult> result = new ArrayList<>();

            result.add(new PluginResult(PluginResult.Status.OK, mode));
            result.add(new PluginResult(PluginResult.Status.OK, iv));
            if (mode.equals("GCM")) {
                // Split the provider's ciphertext+tag layout back into the multipart bridge
                // contract. Register both new arrays so the final cleanup covers their copies.
                byte[] ciphertext = Arrays.copyOf(output, output.length - 16);
                byte[] tag = Arrays.copyOfRange(output, output.length - 16, output.length);

                buffers.add(ciphertext);
                buffers.add(tag);
                result.add(new PluginResult(PluginResult.Status.OK, ciphertext));
                result.add(new PluginResult(PluginResult.Status.OK, tag));
            } else {
                result.add(new PluginResult(PluginResult.Status.OK, output));
                result.add(new PluginResult(PluginResult.Status.OK, (String) null));
            }

            return new PluginResult(PluginResult.Status.OK, result);
        } finally {
            for (byte[] buffer : buffers) Arrays.fill(buffer, (byte) 0);
        }
    }

    private void stream(String action, JSONArray raw, CallbackContext callback) {
        List<byte[]> buffers = new ArrayList<>();
        StreamSession session = null;
        String id = null;
        String transaction = null;

        try {
            CordovaArgs args = new CordovaArgs(raw);

            if (action.equals("open")) {
                if (raw.length() != 0) throw invalid("open does not accept native arguments.");

                if (transactions.size() >= 16) throw new CryptoFailure("RESOURCE_LIMIT", "Too many active AES transactions.");

                id = UUID.randomUUID().toString();
                transactions.put(id, new ArrayList<>());
                callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, id));
                return;
            }

            if (action.equals("commit") || action.equals("rollback")) {
                if (raw.length() != 1 || !(raw.opt(0) instanceof String)) throw invalid("Expected a transaction ID.");

                transaction = (String) raw.opt(0);
                if (!transactions.containsKey(transaction)) throw new CryptoFailure("NOT_FOUND", "Key does not exists!");

                if (action.equals("commit")) {
                    if (owners.containsValue(transaction)) throw invalid("Finalize or abort every session before committing.");

                    // Commit releases rollback ownership without deleting completed files.
                    // Removing this entry earlier would leave finalized outputs outside rollback.
                    transactions.remove(transaction);
                } else rollback(transaction);
                callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, action));
                return;
            }

            if (action.equals("create")) {
                if (raw.length() != 3 || !(raw.opt(0) instanceof JSONObject)) throw invalid("Expected stream options and two keys.");

                JSONObject options = args.getJSONObject(0);

                transaction = string(options, "transactionID");
                if (!transactions.containsKey(transaction)) throw new CryptoFailure("NOT_FOUND", "Key does not exists!");

                String operation = string(options, "operation");

                if (!operation.equals("encrypt") && !operation.equals("decrypt")) throw invalid("operation must be encrypt or decrypt.");

                if (sessions.size() >= 16) throw new CryptoFailure("RESOURCE_LIMIT", "Too many active AES sessions.");

                byte[] key = bytes(args, 1, "key", 16, 32, buffers);

                if (key.length != 16 && key.length != 24 && key.length != 32) throw invalid("key must contain 16, 24 or 32 bytes.");

                byte[] keyHmac = bytes(args, 2, "keyHmac", 1, 1048576, buffers);
                File directory = new File(cordova.getContext().getCacheDir(), "transferchain-aes");

                if (!directory.isDirectory() && !directory.mkdirs()) throw new java.io.IOException("Cache unavailable");

                session = new StreamSession(directory, key, keyHmac, operation.equals("encrypt"));
                id = UUID.randomUUID().toString();
                sessions.put(id, session);
                owners.put(id, transaction);
                callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, id));
                return;
            }

            if (raw.length() != (action.equals("update") ? 2 : 1) || !(raw.opt(0) instanceof String)) {
                throw invalid("Expected a session ID and action arguments.");
            }

            id = (String) raw.opt(0);
            session = sessions.get(id);
            if (session == null) throw new CryptoFailure("NOT_FOUND", "Key does not exists!");

            transaction = owners.get(id);
            if (action.equals("update")) {
                session.update(bytes(args, 1, "data", 0, 1048576, buffers));
                callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, "updated"));
            } else if (action.equals("finalize")) {
                String url = session.finish();

                // Finalizing a session does not commit its transaction. Track the finished
                // file before removing the session so a later callback failure can delete it.
                transactions.get(transaction).add(session.output);
                sessions.remove(id);
                owners.remove(id);
                session.close();
                callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, url));
            } else {
                sessions.remove(id);
                owners.remove(id);
                session.close();
                callback.sendPluginResult(new PluginResult(PluginResult.Status.OK, "aborted"));
            }
        } catch (CryptoFailure error) {
            if (transaction != null) rollback(transaction);
            if (session != null) session.close();
            fail(callback, error.code, error.getMessage());
        } catch (Exception error) {
            if (transaction != null) rollback(transaction);
            if (session != null) session.close();
            fail(callback, "OPERATION_FAILED", "Native AES stream operation failed.");
        } finally {
            for (byte[] buffer : buffers) Arrays.fill(buffer, (byte) 0);
        }
    }

    // Finalized files belong to the transaction until commit. Rollback closes
    // active sessions and deletes outputs registered to this transaction.
    private void rollback(String transaction) {
        for (String id : new ArrayList<>(owners.keySet())) {
            if (transaction.equals(owners.get(id))) {
                sessions.remove(id).close();
                owners.remove(id);
            }
        }

        List<File> files = transactions.remove(transaction);

        if (files != null) for (File file : files) file.delete();
    }

    // Wire format: version(1) | IV(16) | ciphertext | HMAC-SHA512(64).
    // HMAC covers IV and ciphertext; the version byte is validated separately.
    // Decryption spools ciphertext and produces no plaintext before tag validation.
    private static final class StreamSession {
        private final boolean encrypt;

        private final byte[] key;
        private final byte[] iv = new byte[16];
        private Mac mac;
        private Cipher cipher;
        private final File spool;
        private File output;
        private FileOutputStream writer;

        private final byte[] header = new byte[17];
        private int headerSize;

        private byte[] tail = new byte[0];

        // LENGTH TYPES AND OVERFLOW
        // Array indexes/chunk lengths use int. total uses long because it accumulates
        // many chunks; addition must not wrap before checking the 1 GiB stream limit.
        // Decrypt includes 81 envelope bytes, which are excluded from plaintext length.
        // headerSize indexes a fixed 17-byte array; tail retains at most 64 bytes after
        // update. These are different units and must not be substituted for each other.
        // The CTR counter check separately prevents wrapping its 128-bit counter value.
        private long total;
        private boolean completed;

        StreamSession(File directory, byte[] aesKey, byte[] keyHmac, boolean encrypt) throws Exception {
            this.encrypt = encrypt;
            // The bridge input is wiped when create returns. Keep a session-owned copy
            // for later updates/decryption and clear that copy when the session closes.
            this.key = aesKey.clone();
            // WIRE PROTOCOL SECURITY
            // Authenticate IV || ciphertext and append the complete SHA-512 HMAC (64 bytes).
            // AES and HMAC have separate parameters; callers must supply independent keys.
            // The version byte is outside the MAC to match the supplied Go format and is
            // checked separately against the supported value 1. This distinction matters
            // when evolving the format: changing authenticated coverage is a protocol change.
            // Keep Android/iOS/Go vectors aligned for field order, tag size and counter order.
            mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(keyHmac, "HmacSHA512"));
            spool = File.createTempFile("stream-", ".part", directory);
            try {
                writer = new FileOutputStream(spool);
                if (encrypt) {
                    new SecureRandom().nextBytes(iv);
                    cipher = newCipher(true);
                    writer.write(1);
                    writer.write(iv);
                    mac.update(iv);
                }
            } catch (Exception error) { close(); throw error; }
        }

        private Cipher newCipher(boolean encrypt) throws Exception {
            Cipher result = Cipher.getInstance("AES/CTR/NoPadding");

            result.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return result;
        }

        // INCREMENTAL INPUT PARSING
        // Encryption feeds the existing cipher, then adds emitted ciphertext to HMAC and
        // spool. Recreating the cipher for each chunk would restart the counter and break
        // the stream. An empty update must not reset any state.
        //
        // Decryption has three logical regions: a 17-byte version/IV header, ciphertext,
        // and a 64-byte trailing HMAC. These regions can cross any update boundary. Until
        // finalize, the most recent 64 bytes are candidates for the tag and remain in tail.
        // For example, 80 pending bytes yield 16 ciphertext bytes and a 64-byte tail.
        // The spool contains ciphertext only; authentication is completed in finish.
        void update(byte[] data) throws Exception {
            long next = total + data.length;

            if (next > 1073741824L + (encrypt ? 0 : 81)) throw new CryptoFailure("RESOURCE_LIMIT", "AES stream exceeds 1 GiB.");

            total = next;
            if (encrypt) {
                checkCounter(iv, total);
                if (data.length == 0) return;

                byte[] encrypted = cipher.update(data);

                if (encrypted != null) {
                    try { mac.update(encrypted); writer.write(encrypted); }
                    finally { Arrays.fill(encrypted, (byte) 0); }
                }

                return;
            }

            // A chunk may contain only part of the 17-byte header. Accumulate version+IV
            // before treating any remaining bytes as ciphertext or the trailing MAC.
            int offset = Math.min(17 - headerSize, data.length);

            System.arraycopy(data, 0, header, headerSize, offset);
            headerSize += offset;
            if (headerSize < 17) return;

            if (header[0] != 1) throw invalid("Unsupported ctr-with-hmac envelope version.");

            if (total - data.length < 17) {
                System.arraycopy(header, 1, iv, 0, 16);
                mac.update(iv);
            }

            // Chunk boundaries do not identify the HMAC boundary. Retain the last
            // 64 bytes and hash/spool only bytes known to be ciphertext.
            byte[] pending = new byte[tail.length + data.length - offset];

            try {
                System.arraycopy(tail, 0, pending, 0, tail.length);
                System.arraycopy(data, offset, pending, tail.length, data.length - offset);
                int count = Math.max(0, pending.length - 64);

                if (count > 0) { mac.update(pending, 0, count); writer.write(pending, 0, count); }

                Arrays.fill(tail, (byte) 0);
                tail = Arrays.copyOfRange(pending, count, pending.length);
            } finally { Arrays.fill(pending, (byte) 0); }
        }

        // FINALIZATION IS NOT TRANSACTION COMMIT
        // On encryption, flush the cipher, authenticate its final bytes, append the HMAC,
        // and close the writer before promoting the temporary path to a result path.
        // On decryption, validate envelope size and the complete HMAC first. Only then
        // read the ciphertext spool again and write authenticated plaintext to output.
        //
        // An empty plaintext is valid: its encoded stream still has 1 + 16 + 64 bytes.
        // Missing header/tag bytes are malformed input, not an empty file. If any step
        // throws, transaction rollback closes the session and attempts to remove outputs.
        // The caller receives a path here; the transaction retains rollback ownership.
        String finish() throws Exception {
            if (encrypt) {
                byte[] end = cipher.doFinal();

                try { mac.update(end); writer.write(end); }
                finally { Arrays.fill(end, (byte) 0); }

                byte[] tag = mac.doFinal();

                try { writer.write(tag); }
                finally { Arrays.fill(tag, (byte) 0); }

                writer.close();
                writer = null;
                output = new File(spool.getParentFile(), UUID.randomUUID() + ".bin");
                if (!spool.renameTo(output)) throw new java.io.IOException("Unable to finalize stream");
            } else {
                if (headerSize != 17 || tail.length != 64) throw invalid("Incomplete ctr-with-hmac envelope.");

                byte[] expected = mac.doFinal();
                boolean valid;

                try { valid = MessageDigest.isEqual(expected, tail); }
                finally { Arrays.fill(expected, (byte) 0); }

                // Authenticate before the second pass creates the plaintext file.
                // Do not replace this comparison with ordinary array equality.
                if (!valid) throw new CryptoFailure("AUTHENTICATION_FAILED", "AES-CTR HMAC authentication failed.");

                writer.close();
                writer = null;
                checkCounter(iv, total - 81);
                cipher = newCipher(false);
                output = File.createTempFile("result-", ".bin", spool.getParentFile());
                // The tag has passed verification. Decrypt the authenticated spool in bounded
                // chunks so plaintext size does not determine the temporary memory footprint.
                byte[] chunk = new byte[16384];

                try (FileInputStream input = new FileInputStream(spool);
                     FileOutputStream decoded = new FileOutputStream(output)) {
                    int count;

                    while ((count = input.read(chunk)) != -1) {
                        byte[] plain = cipher.update(chunk, 0, count);

                        if (plain != null) {
                            try { decoded.write(plain); }
                            finally { Arrays.fill(plain, (byte) 0); }
                        }
                    }

                    byte[] end = cipher.doFinal();

                    try { decoded.write(end); }
                    finally { Arrays.fill(end, (byte) 0); }
                } finally { Arrays.fill(chunk, (byte) 0); }
            }

            completed = true;
            return output.toURI().toString();
        }

        // SESSION CLEANUP AND OUTPUT OWNERSHIP
        // Close the writer and remove the temporary spool on both success and failure.
        // An incomplete output belongs to this session and must also be removed. A
        // completed output is retained here because transaction rollback/commit now
        // controls it; deleting it unconditionally would break successful finalize.
        //
        // Clear owned key/header/tail buffers and release provider state. Releasing a
        // Cipher/MAC reference is not proof that every provider-internal copy was wiped.
        // File removal in this cleanup path is best-effort; it is not a crash-recovery
        // journal or a guarantee that an OS deletion failure has been repaired.
        void close() {
            if (writer != null) { try { writer.close(); } catch (Exception ignored) { } writer = null; }

            spool.delete();
            if (!completed && output != null) output.delete();
            Arrays.fill(key, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(header, (byte) 0);
            Arrays.fill(tail, (byte) 0);
            cipher = null;
            mac = null;
        }
    }

    private static void checkCounter(byte[] iv, long length) throws CryptoFailure {
        // CTR consumes one 16-byte counter value per block, including a partial block.
        // For 17 bytes it uses the initial counter and initial+1, so test an increment
        // of ceil(length / 16) - 1. Walk the IV as a big-endian integer and propagate
        // carry without narrowing the full 128-bit value into a Java long.
        // A final carry would mean counter wrap and possible keystream reuse.
        long carry = Math.max(0, (length + 15) / 16 - 1);

        for (int index = 15; index >= 0; index--) {
            carry = ((iv[index] & 255) + carry) >>> 8;
        }

        if (carry != 0) throw invalid("CTR counter would wrap for this data length.");
    }

    private static int integer(JSONObject options, String name, int min, int max)
            throws CryptoFailure {
        Object value = options.opt(name);

        if (!(value instanceof Number)) throw invalid(name + " must be an integer.");

        double number = ((Number) value).doubleValue();

        if (!Double.isFinite(number) || number != Math.rint(number) || number < min || number > max) {
            throw invalid(name + " is outside the supported integer range.");
        }

        return (int) number;
    }

    private static String string(JSONObject options, String name) throws CryptoFailure {
        Object value = options.opt(name);

        if (!(value instanceof String)) throw invalid(name + " must be a string.");

        return (String) value;
    }

    private static byte[] bytes(CordovaArgs args, int index, String name, int min, int max,
            List<byte[]> buffers) throws CryptoFailure {
        Object encoded = args.opt(index);

        if (!(encoded instanceof String) || ((String) encoded).length() > 4 * ((max + 2) / 3)) {
            throw invalid(name + " must be an ArrayBuffer within the byte limits.");
        }

        byte[] value;

        try {
            value = args.getArrayBuffer(index);
        } catch (Exception error) {
            throw invalid(name + " must be an ArrayBuffer.");
        }

        buffers.add(value);
        if (value.length < min || value.length > max) {
            throw invalid(name + " is outside the supported byte range.");
        }

        return value;
    }

    private static CryptoFailure invalid(String message) {
        return new CryptoFailure("INVALID_ARGUMENT", message);
    }

    private static final class CryptoFailure extends Exception {
        final String code;

        CryptoFailure(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    private static void fail(CallbackContext callback, String code, String message) {
        JSONObject error = new JSONObject();

        try {
            error.put("code", code);
            error.put("message", message);
            error.put("name", code.equals("INVALID_ARGUMENT") ? "ArgumentError" : "OperationError");
        } catch (JSONException impossible) {
            callback.error("Native crypto operation failed.");
            return;
        }

        callback.error(error);
    }
}
