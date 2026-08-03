package android.view;

public class View {
    public static final int VISIBLE = 0;
    public static final int GONE = 8;

    public void setVisibility(int visibility) {}
    public void setOnClickListener(OnClickListener listener) {}
    public void setBackgroundColor(int color) {}
    public void setPadding(int left, int top, int right, int bottom) {}
    public void setLayoutParams(ViewGroup.LayoutParams params) {}
    public void setTag(Object tag) {}
    public Object getTag() { return null; }
    public View findViewWithTag(Object tag) { return null; }

    public interface OnClickListener {
        void onClick(View v);
    }
}
