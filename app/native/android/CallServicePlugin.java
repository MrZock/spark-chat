package io.github.mrzock.sparkchat;

import android.content.Intent;
import android.os.Build;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

// Schnittstelle für chat.js: CallService.start({ who }) beim Anruf, CallService.stop() beim Auflegen
@CapacitorPlugin(name = "CallService")
public class CallServicePlugin extends Plugin {
    static volatile boolean active = false;

    @PluginMethod
    public void start(PluginCall call) {
        Intent i = new Intent(getContext(), CallService.class).putExtra("who", call.getString("who", ""));
        try {
            if (Build.VERSION.SDK_INT >= 26) getContext().startForegroundService(i); else getContext().startService(i);
            active = true;
            call.resolve();
        } catch (Exception e) {
            call.reject(String.valueOf(e.getMessage()));
        }
    }

    @PluginMethod
    public void stop(PluginCall call) {
        getContext().stopService(new Intent(getContext(), CallService.class));
        active = false;
        call.resolve();
    }
}
