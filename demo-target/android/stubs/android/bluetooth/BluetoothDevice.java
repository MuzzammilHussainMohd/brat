package android.bluetooth;
import android.content.Context;
public class BluetoothDevice {
    public static final int TRANSPORT_LE = 2;
    public String getName() { return null; }
    public String getAddress() { return null; }
    public BluetoothGatt connectGatt(Context context, boolean autoConnect, BluetoothGattCallback callback, int transport) { return null; }
}
