// SPARK Chat – Service Worker: nur für Push-Benachrichtigungen (keine Daten, kein Zwischenspeicher).
// Eine Benachrichtigung enthält absichtlich nur „Du hast eine neue Nachricht“.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  e.waitUntil((async () => {
    let d = {}; try { d = e.data ? e.data.json() : {}; } catch (err) {}
    // App ist gerade offen und sichtbar → keine Benachrichtigung nötig
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (list.some(c => c.visibilityState === 'visible' && c.focused)) return;
    return self.registration.showNotification(d.title || 'SPARK Chat', { body: d.body || 'Du hast eine neue Nachricht', icon: 'icon.png', badge: 'icon.png', tag: 'spark-chat', renotify: true });
  })());
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) if ('focus' in c) return c.focus();
    return self.clients.openWindow(self.registration.scope);
  })());
});
