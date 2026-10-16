package io.github.mrzock.sparkchat;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;

// Vordergrund-Dienst während eines Anrufs: Android erlaubt Mikrofon und Ton im Hintergrund nur so
// (mit sichtbarer Benachrichtigung „Anruf läuft“, wie bei anderen Telefonie-Apps).
public class CallService extends Service {
    static final String CHANNEL = "spark_call";

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Laufende Anrufe", NotificationManager.IMPORTANCE_LOW));
        Intent open = new Intent(this, MainActivity.class).setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        String who = intent != null && intent.getStringExtra("who") != null ? intent.getStringExtra("who") : "";
        Notification n = new NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("SPARK Chat – Anruf läuft")
            .setContentText(who.isEmpty() ? "Tippen, um zurückzukehren" : "mit " + who)
            .setSmallIcon(getApplicationInfo().icon)
            .setOngoing(true)
            .setContentIntent(pi)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .build();
        if (Build.VERSION.SDK_INT >= 30) startForeground(7, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE | ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK);
        else startForeground(7, n);
        return START_NOT_STICKY;
    }
}
