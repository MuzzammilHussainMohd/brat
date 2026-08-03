package android.bluetooth.le;
public class ScanSettings {
    public static final int SCAN_MODE_LOW_LATENCY = 2;
    public static class Builder {
        public Builder setScanMode(int scanMode) { return this; }
        public ScanSettings build() { return null; }
    }
}
