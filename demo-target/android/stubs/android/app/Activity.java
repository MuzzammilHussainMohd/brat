package android.app;
import android.os.Bundle;
import android.content.Context;
import android.view.Window;
public class Activity extends Context {
    public void setContentView(int layoutResID) {}
    public <T extends android.view.View> T findViewById(int id) { return null; }
    protected void onCreate(Bundle savedInstanceState) {}
    protected void onDestroy() {}
    public void runOnUiThread(Runnable action) {}
    public Window getWindow() { return null; }
    public void requestPermissions(String[] permissions, int requestCode) {}
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {}
}
