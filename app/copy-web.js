// Kopiert die Web-App (eine Ebene höher) in www/ – das ist der Inhalt der Android-/iPhone-App
const fs = require('fs'), path = require('path');
const src = path.join(__dirname, '..'), dst = path.join(__dirname, 'www');
fs.rmSync(dst, { recursive: true, force: true }); fs.mkdirSync(dst);
for (const f of ['index.html', 'chat.js', 'chat.css', 'icon.png', 'icon-192.png', 'icon-512.png', 'manifest.json']) fs.copyFileSync(path.join(src, f), path.join(dst, f));
// Capacitor fügt auf Android ein Inline-Skript (Brücke zur App) ein – das muss die Sicherheitsregel erlauben
const ix = path.join(dst, 'index.html');
fs.writeFileSync(ix, fs.readFileSync(ix, 'utf8').replace("script-src 'self' file: blob:", "script-src 'self' 'unsafe-inline' blob:").replace('<link rel="manifest" href="manifest.json">', ''));
console.log('www/ bereit');
