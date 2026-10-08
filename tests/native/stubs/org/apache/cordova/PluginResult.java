package org.apache.cordova;

import java.util.Arrays;
import java.util.List;

public final class PluginResult {
    public enum Status { OK, ERROR }
    public final Status status;
    public final Object value;
    public PluginResult(Status status, org.json.JSONObject value) { this.status = status; this.value = value; }
    public PluginResult(Status status, String value) { this.status = status; this.value = value; }
    public PluginResult(Status status, byte[] value) { this.status = status; this.value = Arrays.copyOf(value, value.length); }
    public PluginResult(Status status, List<PluginResult> value) { this.status = status; this.value = value; }
}
