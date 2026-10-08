package android.content;

public class Context {
    public java.io.File getCacheDir() {
        java.io.File directory = new java.io.File(".build-cache/crypto/session-files");
        directory.mkdirs();
        return directory;
    }
}
