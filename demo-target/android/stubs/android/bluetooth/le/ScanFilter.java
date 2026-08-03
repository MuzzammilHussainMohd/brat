package android.bluetooth.le;
import android.os.ParcelUuid;
public class ScanFilter {
    public static class Builder {
        public Builder setServiceUuid(ParcelUuid uuid) { return this; }
        public Builder setDeviceName(String name) { return this; }
        public ScanFilter build() { return null; }
    }
}
