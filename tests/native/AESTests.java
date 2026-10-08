import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import com.transferchain.aes.AES;

public final class AESTests {
    private static final ExecutorService POOL = Executors.newFixedThreadPool(2);
    private static int checks;

    private static CallbackContext call(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        plugin.cordova = () -> POOL;
        CallbackContext callback = new CallbackContext();
        if (!plugin.execute(action, args, callback)) throw new AssertionError("Unexpected action rejection");
        if (!callback.done.await(45, TimeUnit.SECONDS)) throw new AssertionError("Native call timeout");
        // The production guard is released in finally after the callback.
        POOL.submit(() -> {}).get();
        return callback;
    }

    private static Object success(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        CallbackContext callback = call(plugin, action, args);
        if (callback.failure != null) throw new AssertionError(callback.failure.toString());
        return callback.result instanceof PluginResult ? ((PluginResult) callback.result).value : callback.result;
    }

    private static void rejected(CordovaPlugin plugin, String action, JSONArray args, String code) throws Exception {
        CallbackContext callback = call(plugin, action, args);
        if (callback.result != null) throw new AssertionError("Rejected operation released output");
        if (!(callback.failure instanceof JSONObject) ||
                !((JSONObject) callback.failure).getString("code").equals(code) ||
                ((JSONObject) callback.failure).getString("message").isBlank()) {
            throw new AssertionError("Expected " + code + ", received " + callback.failure);
        }
        checks++;
    }

    private static String binary(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    private static String hex(byte[] value) { return HexFormat.of().formatHex(value); }
    private static byte[] bytes(String value) { return HexFormat.of().parseHex(value); }
    private static void equal(Object actual, Object expected) {
        if (!actual.equals(expected)) throw new AssertionError("Vector mismatch: " + actual + " != " + expected);
        checks++;
    }
    private static JSONArray aes(String mode, byte[] key, byte[] data, byte[] iv, byte[] aad, byte[] tag) {
        return new JSONArray().put(new JSONObject().put("mode", mode)).put(binary(key)).put(binary(data))
            .put(iv == null ? JSONObject.NULL : binary(iv))
            .put(aad == null ? JSONObject.NULL : binary(aad))
            .put(tag == null ? JSONObject.NULL : binary(tag));
    }
    @SuppressWarnings("unchecked")
    private static List<PluginResult> encrypted(String mode, byte[] key, byte[] data, byte[] iv, byte[] aad) throws Exception {
        return (List<PluginResult>) success(new AES(), "encrypt", aes(mode, key, data, iv, aad, null));
    }
    private static byte[] part(List<PluginResult> result, int index) { return (byte[]) result.get(index).value; }

    private static void aes() throws Exception {
        byte[] zeroKey = new byte[16], zeroIv = new byte[12];
        List<PluginResult> gcm = encrypted("GCM", zeroKey, new byte[16], zeroIv, null);
        equal(hex(part(gcm, 2)), "0388dace60b6a392f328c2b971b2fe78");
        equal(hex(part(gcm, 3)), "ab6e47d42cec13bdf53a67b21257bddf");
        List<PluginResult> empty = encrypted("GCM", zeroKey, new byte[0], zeroIv, null);
        equal(part(empty, 2).length, 0);
        equal(hex(part(empty, 3)), "58e2fccefa7e3061367f1d57a4e7455a");
        byte[] key = bytes("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] data = bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        List<PluginResult> ctr = encrypted("CTR", key, data, iv, null);
        equal(hex(part(ctr, 2)), "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");
        equal(ctr.get(3).value == null, true);
        for (String mode : new String[] {"GCM", "CTR"}) {
            for (int size : new int[] {16, 24, 32}) {
                byte[] k = new byte[size], message = "unaligned 🔑".getBytes(StandardCharsets.UTF_8);
                byte[] aad = mode.equals("GCM") ? new byte[] {1, 2, 3} : null;
                List<PluginResult> result = encrypted(mode, k, message, null, aad);
                byte[] decoded = (byte[]) success(new AES(), "decrypt",
                    aes(mode, k, part(result, 2), part(result, 1), aad, mode.equals("GCM") ? part(result, 3) : null));
                equal(hex(decoded), hex(message));
                List<PluginResult> other = encrypted(mode, k, message, null, aad);
                equal(Arrays.equals(part(result, 1), part(other, 1)), false);
                if (mode.equals("GCM")) {
                    byte[] tag = part(result, 3).clone(); tag[0] ^= 1;
                    rejected(new AES(), "decrypt", aes(mode, k, part(result, 2), part(result, 1), aad, tag), "AUTHENTICATION_FAILED");
                    rejected(new AES(), "decrypt", aes(mode, k, part(result, 2), part(result, 1), new byte[] {9}, part(result, 3)), "AUTHENTICATION_FAILED");
                    byte[] altered = part(result, 2).clone(); altered[0] ^= 1;
                    rejected(new AES(), "decrypt", aes(mode, k, altered, part(result, 1), aad, part(result, 3)), "AUTHENTICATION_FAILED");
                }
            }
        }
        rejected(new AES(), "encrypt", aes("CBC", key, data, iv, null, null), "INVALID_ARGUMENT");
        rejected(new AES(), "encrypt", aes("GCM", new byte[17], data, zeroIv, null, null), "INVALID_ARGUMENT");
        rejected(new AES(), "encrypt", aes("CTR", key, data, iv, new byte[0], null), "INVALID_ARGUMENT");
        rejected(new AES(), "decrypt", aes("GCM", zeroKey, new byte[0], zeroIv, null, null), "INVALID_ARGUMENT");
        byte[] last = new byte[16]; Arrays.fill(last, (byte) 255);
        rejected(new AES(), "encrypt", aes("CTR", key, new byte[17], last, null, null), "INVALID_ARGUMENT");
        equal(part(encrypted("CTR", key, new byte[16], last, null), 2).length, 16);
    }

    private static String begin(AES plugin) throws Exception {
        return (String) success(plugin, "open", new JSONArray());
    }

    private static String create(AES plugin, String transaction, byte[] key, byte[] keyHmac, String operation) throws Exception {
        return (String) success(plugin, "create", new JSONArray().put(new JSONObject()
                .put("transactionID", transaction).put("operation", operation)).put(binary(key)).put(binary(keyHmac)));
    }

    private static void update(AES plugin, String id, byte[] data, int chunkSize) throws Exception {
        for (int offset = 0; offset < data.length; offset += chunkSize) {
            success(plugin, "update", new JSONArray().put(id).put(binary(Arrays.copyOfRange(data, offset, Math.min(data.length, offset + chunkSize)))));
        }
    }

    private static Path finish(AES plugin, String id) throws Exception {
        return Path.of(java.net.URI.create((String) success(plugin, "finalize", new JSONArray().put(id))));
    }

    private static void authenticatedCTR() throws Exception {
        AES plugin = new AES();
        JSONArray vectors = new JSONArray(Files.readString(Path.of(System.getProperty("pluginTestRoot", "."), "tests/fixtures/aes-ctr-hmac-vectors.json")));
        for (int index = 0; index < vectors.length(); index++) {
            JSONObject vector = vectors.getJSONObject(index);
            for (int chunk : new int[] {1, 16, 17, 63, 64, 65, 16384}) {
                String transaction = begin(plugin);
                String id = create(plugin, transaction, bytes(vector.getString("key")), bytes(vector.getString("keyHmac")), "decrypt");
                update(plugin, id, bytes(vector.getString("envelope")), chunk);
                Path output = finish(plugin, id);
                equal(hex(Files.readAllBytes(output)), vector.getString("data"));
                success(plugin, "rollback", new JSONArray().put(transaction));
                equal(Files.exists(output), false);
            }
        }
        byte[] key = new byte[32], keyHmac = new byte[64];
        Arrays.fill(key, (byte) 0x5A);
        Arrays.fill(keyHmac, (byte) 0xA5);
        for (int length : new int[] {0, 1, 15, 16, 17, 16319, 16320, 16321, 16384, 16385, 1048576, 2097153}) {
            byte[] plain = new byte[length]; Arrays.fill(plain, (byte) 0xA5);
            String transaction = begin(plugin);
            String id = create(plugin, transaction, key, keyHmac, "encrypt");
            update(plugin, id, plain, 7919);
            Path sealed = finish(plugin, id);
            byte[] envelope = Files.readAllBytes(sealed);
            equal(envelope.length, length + 81);
            equal(envelope[0], (byte) 1);
            String decrypt = create(plugin, transaction, key, keyHmac, "decrypt");
            update(plugin, decrypt, envelope, 8179);
            Path output = finish(plugin, decrypt);
            equal(Arrays.equals(Files.readAllBytes(output), plain), true);
            success(plugin, "commit", new JSONArray().put(transaction));
            equal(Files.exists(output), true);
            Files.delete(output); Files.delete(sealed);
            rejected(plugin, "update", new JSONArray().put(id).put(binary(new byte[0])), "NOT_FOUND");
        }
        JSONObject vector = vectors.getJSONObject(2);
        byte[] envelope = bytes(vector.getString("envelope"));
        for (int position = 0; position < envelope.length; position++) {
            String transaction = begin(plugin);
            String id = create(plugin, transaction, bytes(vector.getString("key")), bytes(vector.getString("keyHmac")), "decrypt");
            byte[] altered = envelope.clone(); altered[position] ^= 1;
            if (position == 0) {
                rejected(plugin, "update", new JSONArray().put(id).put(binary(altered)), "INVALID_ARGUMENT");
            } else {
                update(plugin, id, altered, 7);
                rejected(plugin, "finalize", new JSONArray().put(id), "AUTHENTICATION_FAILED");
            }
            rejected(plugin, "commit", new JSONArray().put(transaction), "NOT_FOUND");
        }
        for (int length = 0; length < envelope.length; length++) {
            String transaction = begin(plugin);
            String id = create(plugin, transaction, bytes(vector.getString("key")), bytes(vector.getString("keyHmac")), "decrypt");
            update(plugin, id, Arrays.copyOf(envelope, length), 13);
            rejected(plugin, "finalize", new JSONArray().put(id), length < 81 ? "INVALID_ARGUMENT" : "AUTHENTICATION_FAILED");
        }
        String transaction = begin(plugin);
        String id = create(plugin, transaction, key, keyHmac, "encrypt");
        Path completed = finish(plugin, id);
        String unfinished = create(plugin, transaction, key, keyHmac, "encrypt");
        rejected(plugin, "update", new JSONArray().put(unfinished).put(binary(new byte[1048577])), "INVALID_ARGUMENT");
        equal(Files.exists(completed), false);
        transaction = begin(plugin);
        id = create(plugin, transaction, key, keyHmac, "encrypt");
        java.lang.reflect.Field sessionField = AES.class.getDeclaredField("sessions");
        sessionField.setAccessible(true);
        Object session = ((java.util.Map<?, ?>) sessionField.get(plugin)).get(id);
        java.lang.reflect.Field keyField = session.getClass().getDeclaredField("key");
        keyField.setAccessible(true);
        byte[] ownedKey = (byte[]) keyField.get(session);
        equal(ownedKey[0], (byte) 0x5A);
        success(plugin, "abort", new JSONArray().put(id));
        equal(Arrays.equals(ownedKey, new byte[ownedKey.length]), true);
        equal(key[0], (byte) 0x5A);
        success(plugin, "commit", new JSONArray().put(transaction));
        transaction = begin(plugin);
        id = create(plugin, transaction, key, keyHmac, "encrypt");
        rejected(plugin, "commit", new JSONArray().put(transaction), "INVALID_ARGUMENT");
        rejected(plugin, "finalize", new JSONArray().put(id), "NOT_FOUND");
        Path directory = Path.of(".build-cache/crypto/session-files/transferchain-aes");
        try (var entries = Files.list(directory)) { equal(entries.count(), 0L); }
    }

    public static void main(String[] args) throws Exception {
        try {
            aes(); authenticatedCTR();
            System.out.println("PASS: " + checks + " checks");
        } finally { POOL.shutdownNow(); }
    }
}
