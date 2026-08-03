package android.app;
import android.content.Context;
import android.content.DialogInterface;
import android.widget.ListAdapter;
public class AlertDialog {
    public static class Builder {
        public Builder(Context context) {}
        public Builder setTitle(String title) { return this; }
        public Builder setAdapter(ListAdapter adapter, DialogInterface.OnClickListener listener) { return this; }
        public Builder setNegativeButton(String text, DialogInterface.OnClickListener listener) { return this; }
        public Builder setNeutralButton(String text, DialogInterface.OnClickListener listener) { return this; }
        public AlertDialog show() { return new AlertDialog(); }
    }
}
