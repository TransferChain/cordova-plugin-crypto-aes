package org.apache.cordova;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import org.json.JSONObject;

public class CallbackContext {
    public Object result;
    public Object failure;
    public final CountDownLatch done = new CountDownLatch(1);
    public void sendPluginResult(PluginResult value) {
        if (value.status == PluginResult.Status.ERROR) failure = value.value;
        else result = value;
        done.countDown();
    }
    public void success(String value) { result = value; done.countDown(); }
    public void success(JSONObject value) { result = value; done.countDown(); }
    public void success(byte[] value) { result = Arrays.copyOf(value, value.length); done.countDown(); }
    public void error(String value) { failure = value; done.countDown(); }
    public void error(JSONObject value) { failure = value; done.countDown(); }
}
