package android.bluetooth;
import java.util.UUID;
import java.util.List;
public class BluetoothGatt {
    public static final int GATT_SUCCESS = 0;
    public static final int GATT_INSUFFICIENT_ENCRYPTION = 15;
    public static final int GATT_INSUFFICIENT_AUTHENTICATION = 5;
    public boolean discoverServices() { return false; }
    public BluetoothGattService getService(UUID uuid) { return null; }
    public List<BluetoothGattService> getServices() { return null; }
    public boolean setCharacteristicNotification(BluetoothGattCharacteristic characteristic, boolean enable) { return false; }
    public boolean writeDescriptor(BluetoothGattDescriptor descriptor) { return false; }
    public boolean writeCharacteristic(BluetoothGattCharacteristic characteristic) { return false; }
    public int writeCharacteristic(BluetoothGattCharacteristic characteristic, byte[] value, int writeType) { return 0; }
    public void disconnect() {}
    public void close() {}
}
