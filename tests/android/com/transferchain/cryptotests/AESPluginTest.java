package com.transferchain.cryptotests;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Base64;
import androidx.appcompat.app.AppCompatActivity;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import com.transferchain.aes.AES;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaPreferences;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

@RunWith(AndroidJUnit4.class)
public class AESPluginTest {
    private ExecutorService pool;
    private TestCordova cordova;

    @Before public void setUp() {
        pool = Executors.newFixedThreadPool(2);
        cordova = new TestCordova(pool);
    }

    @After public void tearDown() throws Exception {
        pool.shutdown();
        assertTrue("Native work did not finish", pool.awaitTermination(60, TimeUnit.SECONDS));
    }

    private PluginResult call(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        // A stream reuses one plugin instance across create/update/finalize.
        // Cordova initializes that instance once; repeated bootstrap asserts.
        if (plugin.cordova == null) plugin.privateInitialize("test", cordova, null, new CordovaPreferences());
        Capture callback = new Capture();
        assertTrue(plugin.execute(action, args, callback));
        assertTrue("Native callback timed out", callback.done.await(60, TimeUnit.SECONDS));
        assertEquals(1, callback.count);
        return callback.result;
    }

    private PluginResult ok(CordovaPlugin plugin, String action, JSONArray args) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals("Native operation rejected", PluginResult.Status.OK.ordinal(), result.getStatus());
        return result;
    }

    private void rejects(CordovaPlugin plugin, String action, JSONArray args, String code) throws Exception {
        PluginResult result = call(plugin, action, args);
        assertEquals(PluginResult.Status.ERROR.ordinal(), result.getStatus());
        JSONObject error = new JSONObject(result.getMessage());
        assertEquals(code, error.getString("code"));
        assertFalse(error.getString("message").isEmpty());
    }

    private static String binary(byte[] data) { return Base64.encodeToString(data, Base64.NO_WRAP); }
    private static byte[] data(PluginResult result) {
        assertEquals(PluginResult.MESSAGE_TYPE_ARRAYBUFFER, result.getMessageType());
        return Base64.decode(result.getMessage(), Base64.DEFAULT);
    }
    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder();
        for (byte value : data) out.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return out.toString();
    }
    private static byte[] unhex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }
    private static JSONArray aes(String mode, byte[] key, byte[] data, byte[] iv, byte[] aad, byte[] tag) throws Exception {
        return new JSONArray().put(new JSONObject().put("mode", mode)).put(binary(key)).put(binary(data))
            .put(iv == null ? JSONObject.NULL : binary(iv)).put(aad == null ? JSONObject.NULL : binary(aad))
            .put(tag == null ? JSONObject.NULL : binary(tag));
    }

    @Test public void gcmNistVectorAndTamperRejection() throws Exception {
        byte[] key = new byte[16], iv = new byte[12];
        PluginResult encrypted = ok(new AES(), "encrypt", aes("GCM", key, new byte[16], iv, null, null));
        assertEquals(4, encrypted.getMultipartMessagesSize());
        byte[] ciphertext = data(encrypted.getMultipartMessage(2));
        byte[] tag = data(encrypted.getMultipartMessage(3));
        assertEquals("0388dace60b6a392f328c2b971b2fe78", hex(ciphertext));
        assertEquals("ab6e47d42cec13bdf53a67b21257bddf", hex(tag));
        assertArrayEquals(new byte[16], data(ok(new AES(), "decrypt", aes("GCM", key, ciphertext, iv, null, tag))));
        tag[0] ^= 1;
        rejects(new AES(), "decrypt", aes("GCM", key, ciphertext, iv, null, tag), "AUTHENTICATION_FAILED");
    }

    @Test public void ctrNistVectorAndUnsupportedAad() throws Exception {
        byte[] key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] plaintext = unhex("6bc1bee22e409f96e93d7e117393172a");
        PluginResult encrypted = ok(new AES(), "encrypt", aes("CTR", key, plaintext, iv, null, null));
        byte[] ciphertext = data(encrypted.getMultipartMessage(2));
        assertEquals("874d6191b620e3261bef6864990db6ce", hex(ciphertext));
        assertArrayEquals(plaintext, data(ok(new AES(), "decrypt", aes("CTR", key, ciphertext, iv, null, null))));
        rejects(new AES(), "encrypt", aes("CTR", key, plaintext, iv, new byte[0], null), "INVALID_ARGUMENT");
    }

    @Test public void aesKeySizesFreshIvAndEmptyData() throws Exception {
        for (String mode : new String[] {"GCM", "CTR"}) {
            for (int size : new int[] {16, 24, 32}) {
                byte[] key = new byte[size];
                PluginResult first = ok(new AES(), "encrypt", aes(mode, key, new byte[0], null, null, null));
                PluginResult second = ok(new AES(), "encrypt", aes(mode, key, new byte[0], null, null, null));
                byte[] iv = data(first.getMultipartMessage(1));
                assertFalse(Arrays.equals(iv, data(second.getMultipartMessage(1))));
                assertEquals(0, data(ok(new AES(), "decrypt", aes(mode, key,
                    data(first.getMultipartMessage(2)), iv, null,
                    mode.equals("GCM") ? data(first.getMultipartMessage(3)) : null))).length);
            }
        }
    }

    private String begin(AES plugin) throws Exception {
        return new org.json.JSONTokener(ok(plugin, "open", new JSONArray()).getMessage()).nextValue().toString();
    }

    private String create(AES plugin, String transaction, String operation, byte[] key, byte[] keyHmac) throws Exception {
        PluginResult result = ok(plugin, "create", new JSONArray().put(new JSONObject()
                .put("transactionID", transaction).put("operation", operation)).put(binary(key)).put(binary(keyHmac)));
        return new org.json.JSONTokener(result.getMessage()).nextValue().toString();
    }

    private java.io.File finish(AES plugin, String id) throws Exception {
        String url = new org.json.JSONTokener(ok(plugin, "finalize", new JSONArray().put(id)).getMessage()).nextValue().toString();
        return new java.io.File(java.net.URI.create(url));
    }

    @Test public void authenticatedStreamRoundtripRollbackAndAbort() throws Exception {
        AES plugin = new AES();
        for (int keySize : new int[] {16, 24, 32}) {
            String transaction = begin(plugin);
            byte[] key = new byte[keySize], keyHmac = new byte[64], plain = new byte[16385];
            Arrays.fill(plain, (byte) 0xA5);
            String id = create(plugin, transaction, "encrypt", key, keyHmac);
            for (int offset = 0; offset < plain.length; offset += 19) {
                ok(plugin, "update", new JSONArray().put(id).put(binary(Arrays.copyOfRange(plain, offset, Math.min(plain.length, offset + 19)))));
            }
            java.io.File sealed = finish(plugin, id);
            byte[] envelope = java.nio.file.Files.readAllBytes(sealed.toPath());
            assertEquals(plain.length + 81, envelope.length);
            String decrypt = create(plugin, transaction, "decrypt", key, keyHmac);
            for (int offset = 0; offset < envelope.length; offset += 31) {
                ok(plugin, "update", new JSONArray().put(decrypt).put(binary(Arrays.copyOfRange(envelope, offset, Math.min(envelope.length, offset + 31)))));
            }
            java.io.File decoded = finish(plugin, decrypt);
            assertArrayEquals(plain, java.nio.file.Files.readAllBytes(decoded.toPath()));
            ok(plugin, "rollback", new JSONArray().put(transaction));
            assertFalse(sealed.exists()); assertFalse(decoded.exists());
            transaction = begin(plugin);
            id = create(plugin, transaction, "encrypt", key, keyHmac);
            ok(plugin, "abort", new JSONArray().put(id));
            ok(plugin, "commit", new JSONArray().put(transaction));
            rejects(plugin, "finalize", new JSONArray().put(id), "NOT_FOUND");
        }
    }

    @Test public void authenticatedStreamRejectsTamperedGoVector() throws Exception {
        AES plugin = new AES();
        byte[] key = new byte[16], keyHmac = new byte[129];
        Arrays.fill(key, (byte) 0x10); Arrays.fill(keyHmac, (byte) 0x42);
        byte[] envelope = unhex("0113131313131313131313131313131313d97374e0b251a98a84492b285372ed34684c1b99505f021fe2cb5b0149ba531d500bd458481fab066863598ad3ab65f6d006b150ad18cdd33c73f9cafd0ed3ccdd4e5c25db9ebb2f5759dfbebbd9d1e373");
        String transaction = begin(plugin), id = create(plugin, transaction, "decrypt", key, keyHmac);
        ok(plugin, "update", new JSONArray().put(id).put(binary(envelope)));
        java.io.File decoded = finish(plugin, id);
        byte[] expected = new byte[17]; Arrays.fill(expected, (byte) 0x57);
        assertArrayEquals(expected, java.nio.file.Files.readAllBytes(decoded.toPath()));
        ok(plugin, "rollback", new JSONArray().put(transaction));
        for (int position : new int[] {1, 16, 17, 33, 34, 97}) {
            transaction = begin(plugin); id = create(plugin, transaction, "decrypt", key, keyHmac);
            byte[] changed = envelope.clone(); changed[position] ^= 1;
            ok(plugin, "update", new JSONArray().put(id).put(binary(changed)));
            rejects(plugin, "finalize", new JSONArray().put(id), "AUTHENTICATION_FAILED");
            rejects(plugin, "commit", new JSONArray().put(transaction), "NOT_FOUND");
        }
    }

    private static class Capture extends CallbackContext {
        final CountDownLatch done = new CountDownLatch(1);
        volatile PluginResult result;
        volatile int count;
        Capture() { super("test", null); }
        @Override public synchronized void sendPluginResult(PluginResult value) {
            result = value;
            count++;
            done.countDown();
        }
    }

    private static class TestCordova implements CordovaInterface {
        final ExecutorService executor;
        TestCordova(ExecutorService executor) { this.executor = executor; }
        @Override public ExecutorService getThreadPool() { return executor; }
        @Override public Context getContext() { return InstrumentationRegistry.getInstrumentation().getTargetContext(); }
        @Override public AppCompatActivity getActivity() { return null; }
        @Override public void startActivityForResult(CordovaPlugin plugin, Intent intent, int code) { throw new UnsupportedOperationException(); }
        @Override public void setActivityResultCallback(CordovaPlugin plugin) { throw new UnsupportedOperationException(); }
        @Override public Object onMessage(String id, Object data) { return null; }
        @Override public void requestPermission(CordovaPlugin plugin, int code, String permission) { throw new UnsupportedOperationException(); }
        @Override public void requestPermissions(CordovaPlugin plugin, int code, String[] permissions) { throw new UnsupportedOperationException(); }
        @Override public boolean hasPermission(String permission) { return true; }
    }
}
