package org.apache.cordova;

import org.json.JSONArray;
import org.json.JSONObject;

public final class CordovaArgs {
    private final JSONArray args;
    public CordovaArgs(JSONArray args) { this.args = args; }
    public Object opt(int index) { return args.opt(index); }
    public boolean isNull(int index) { return args.isNull(index); }
    public JSONObject getJSONObject(int index) { return args.getJSONObject(index); }
    public byte[] getArrayBuffer(int index) {
        return java.util.Base64.getDecoder().decode(args.getString(index));
    }
}
