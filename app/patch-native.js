// Passt die erzeugten Android-/iOS-Projekte an: Mikrofon, Benachrichtigungen, Hintergrund-Ton, Versionsnummer
const fs = require('fs'), path = require('path');
const ver = require('./package.json').version, build = String(process.env.GITHUB_RUN_NUMBER || 1);
const which = process.argv[2];
if (which === 'android') {
  const mf = path.join(__dirname, 'android/app/src/main/AndroidManifest.xml');
  let s = fs.readFileSync(mf, 'utf8');
  const perms = ['RECORD_AUDIO', 'MODIFY_AUDIO_SETTINGS', 'POST_NOTIFICATIONS', 'WAKE_LOCK'].filter(p => !s.includes('android.permission.' + p))
    .map(p => '    <uses-permission android:name="android.permission.' + p + '" />').join('\n');
  s = s.replace('</manifest>', perms + '\n</manifest>');
  fs.writeFileSync(mf, s);
  const gr = path.join(__dirname, 'android/app/build.gradle');
  let g = fs.readFileSync(gr, 'utf8');
  g = g.replace(/versionCode \d+/, 'versionCode ' + build).replace(/versionName "[^"]*"/, 'versionName "' + ver + '"');
  fs.writeFileSync(gr, g);
  console.log('Android angepasst (' + ver + ' / ' + build + ')');
} else if (which === 'ios') {
  const pl = path.join(__dirname, 'ios/App/App/Info.plist');
  let s = fs.readFileSync(pl, 'utf8');
  const add = (k, v) => { if (!s.includes('<key>' + k + '</key>')) s = s.replace(/<\/dict>\s*<\/plist>\s*$/, '\t<key>' + k + '</key>\n\t' + v + '\n</dict>\n</plist>\n'); };
  add('NSMicrophoneUsageDescription', '<string>SPARK Chat braucht das Mikrofon für Sprachanrufe und Sprachnachrichten.</string>');
  add('UIBackgroundModes', '<array>\n\t\t<string>audio</string>\n\t</array>');   // Anruf läuft im Hintergrund weiter
  s = s.replace(/(<key>CFBundleShortVersionString<\/key>\s*<string>)[^<]*(<\/string>)/, '$1' + ver + '$2').replace(/(<key>CFBundleVersion<\/key>\s*<string>)[^<]*(<\/string>)/, '$1' + build + '$2');
  fs.writeFileSync(pl, s);
  console.log('iOS angepasst (' + ver + ' / ' + build + ')');
}
