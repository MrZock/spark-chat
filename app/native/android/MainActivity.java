package io.github.mrzock.sparkchat;

import android.os.Bundle;
import android.webkit.WebView;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        registerPlugin(CallServicePlugin.class);
        super.onCreate(savedInstanceState);
    }

    // Während eines Anrufs die WebView nicht anhalten – sonst stoppen Ton und Mikrofon, sobald die App im Hintergrund ist
    private void keepAlive() {
        if (!CallServicePlugin.active || getBridge() == null) return;
        WebView wv = getBridge().getWebView();
        if (wv == null) return;
        wv.onResume();
        wv.resumeTimers();
    }

    @Override
    public void onPause() { super.onPause(); keepAlive(); }

    @Override
    public void onStop() { super.onStop(); keepAlive(); }
}
