package android.bluetooth.le;
public abstract class ScanCallback {
    public void onScanResult(int callbackType, ScanResult result) {}
    public void onScanFailed(int errorCode) {}
}
