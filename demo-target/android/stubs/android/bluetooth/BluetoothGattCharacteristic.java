package android.bluetooth;
import java.util.UUID;
public class BluetoothGattCharacteristic {
    public static final int WRITE_TYPE_DEFAULT = 2;
    public static final int WRITE_TYPE_NO_RESPONSE = 1;
    public void setValue(byte[] value) {}
    public byte[] getValue() { return null; }
    public void setWriteType(int writeType) {}
    public BluetoothGattDescriptor getDescriptor(UUID uuid) { return null; }
}
