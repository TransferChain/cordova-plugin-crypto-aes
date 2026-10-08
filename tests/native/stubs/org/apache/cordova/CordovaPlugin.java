package org.apache.cordova;

import java.util.concurrent.ExecutorService;
import org.json.JSONArray;

public class CordovaPlugin {
    public CordovaInterface cordova;
    public boolean execute(String action, JSONArray args, CallbackContext callback) { return false; }
    public void onReset() { }
    public void onDestroy() { }
    public interface CordovaInterface {
        ExecutorService getThreadPool();
        default android.content.Context getContext() { return new android.content.Context(); }
    }
}
