// SPARK Chat – Freunde, Gruppen, Ende-zu-Ende-verschlüsselte Nachrichten, Bilder, Sprachnachrichten,
// Sprachanrufe und BLACKOUT-Einladungen.
// Sicherheit: Aus Passwort + Benutzername werden auf dem Gerät zwei Schlüssel berechnet (PBKDF2):
//  • „auth“ geht zum Server (der speichert davon nur einen Hash) – das Passwort selbst verlässt nie das Gerät
//  • „wrap“ bleibt hier und verschlüsselt den privaten Schlüssel (ECDH P-256) und den Chatverlauf
// Privatchat: AES-GCM mit einem Schlüssel, den nur die beiden aus ihren Schlüsselpaaren ableiten können.
// Gruppe: Inhalt mit einem Zufallsschlüssel verschlüsselt, der für jedes Mitglied einzeln verpackt wird.
'use strict';
(() => {
const VERSION = 'Alpha 1.1.3';
const $ = id => document.getElementById(id);
const SITE = 'https://mrzock.github.io/spark/';
const LINKS = { terms: SITE + 'nutzungsbedingungen.html', privacy: SITE + 'datenschutz.html#chat', contact: SITE + 'datenschutz.html#kontakt', site: 'https://mrzock.github.io/spark-chat-web/' };
const GAME_WEB = 'https://mrzock.github.io/nachtwache/';
const SPARK = window.SPARK || null;   // im SPARK-Launcher: Spiele starten, sicher angemeldet bleiben, Fenster zeigen
// Android-/iPhone-App (Capacitor): Benachrichtigungen über das Handy-System
const CAP = window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform() ? window.Capacitor : null;
const LN = CAP && CAP.Plugins && CAP.Plugins.LocalNotifications;
const CALLSVC = CAP && CAP.Plugins && CAP.Plugins.CallService;   // Android: Vordergrund-Dienst, damit der Anruf im Hintergrund weiterläuft
if (LN) LN.requestPermissions().catch(() => {});
const SERVER = (() => {
  let s = ''; try { s = new URLSearchParams(location.search).get('server') || ''; } catch (e) {}
  if (!s) return 'wss://nachtwache.onrender.com/chat';
  const host = s.replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '');
  return (/^(localhost|127\.)/.test(host) ? 'ws://' : 'wss://') + host + '/chat';
})();
const NAME_RE = /^[A-Za-z0-9_.-]{3,20}$/;
const MAX_MEDIA = 420 * 1024;
const REACTS = ['👍', '❤️', '😂', '😮', '😢', '🔥'];
const te = new TextEncoder(), td = new TextDecoder();
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const lsGet = (k, d) => { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} };
const prefs = Object.assign({ notify: true, sound: true, theme: 'dark', accent: '#2ee6ff', size: 'm', bubble: 'cut', bg: 'grid', sink: '' }, lsGet('sparkchat.prefs', {}));
const savePrefs = () => lsSet('sparkchat.prefs', prefs);
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- Aussehen: Theme, Akzentfarbe, Schriftgröße, Blasen, Hintergrund
const ACCENTS = [['Cyan', '#2ee6ff'], ['Orange', '#ff7a2a'], ['Gelb', '#ffc93c'], ['Grün', '#2fd07a'], ['Blau', '#3d8bff'], ['Lila', '#8a5cff'], ['Pink', '#ff4fa3'], ['Rot', '#ff4d4d']];
const sysDark = window.matchMedia ? matchMedia('(prefers-color-scheme: dark)') : null;
function applyLook() {
  const h = document.documentElement, theme = prefs.theme === 'system' ? (sysDark && !sysDark.matches ? 'light' : 'dark') : prefs.theme;
  h.dataset.theme = theme; h.dataset.size = prefs.size; h.dataset.bubble = prefs.bubble; h.dataset.bg = prefs.bg;
  h.style.setProperty('--acc', prefs.accent);
  const meta = document.querySelector('meta[name="theme-color"]'); if (meta) meta.content = theme === 'light' ? '#eef1f7' : theme === 'oled' ? '#000000' : '#05060b';
}
if (sysDark && sysDark.addEventListener) sysDark.addEventListener('change', () => prefs.theme === 'system' && applyLook());
applyLook();

// ---------- Kryptografie (WebCrypto)
const C = crypto.subtle;
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => new Uint8Array((h.match(/../g) || []).map(x => parseInt(x, 16)));
const b64 = buf => { const a = new Uint8Array(buf); let s = ''; for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => { const bin = atob(s), a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a; };
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
async function deriveKeys(name, pw, saltHex) {
  const base = await C.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await C.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: cat(unhex(saltHex), te.encode(name.toLowerCase())), iterations: 300000 }, base, 512));
  return { auth: hex(bits.slice(0, 32)), wrapRaw: bits.slice(32) };
}
const aesKey = raw => C.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
async function hkdfKey(raw, info, salt) {
  const k = await C.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  return C.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: te.encode(salt || 'spark-chat'), info: te.encode(info) }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encWith(key, bytes, ad) {
  const iv = rnd(12), opt = { name: 'AES-GCM', iv }; if (ad) opt.additionalData = te.encode(ad);
  return cat(iv, new Uint8Array(await C.encrypt(opt, key, bytes)));
}
async function decWith(key, all, ad) {
  const opt = { name: 'AES-GCM', iv: all.subarray(0, 12) }; if (ad) opt.additionalData = te.encode(ad);
  return new Uint8Array(await C.decrypt(opt, key, all.subarray(12)));
}
async function wrapPriv(priv, wrapRaw) { return b64(await encWith(await aesKey(wrapRaw), new Uint8Array(await C.exportKey('pkcs8', priv)))); }
async function unwrapPriv(s, wrapRaw) { return C.importKey('pkcs8', await decWith(await aesKey(wrapRaw), unb64(s)), ECDH, false, ['deriveBits']); }

// ---------- Zustand
// Unterhaltungen: Freund = sein Schlüssel (kleingeschriebener Name), Gruppe = „g:<id>“
let ws = null, me = null, pendingKeys = null, stayLogged = false, manualClose = false, retryN = 0, retryT = null;
let friends = new Map(), groups = new Map(), inReq = [], outReq = [], blocked = [], sel = null;
const hist = new Map(), shared = new Map(), unread = {}, typingT = {};
let histKey = null, pins = {}, nicks = {}, lastTyping = 0, call = null, actNow = '', replyTo = null, editId = null, openAfter = null;
const isG = ck => typeof ck === 'string' && ck.startsWith('g:');
const gidOf = ck => ck.slice(2);
const nameOf = k => { const f = friends.get(k); if (f) return f.u; for (const g of groups.values()) { const m = g.members.find(x => x.key === k); if (m) return m.u; } return k; };
const display = k => (me && k === me.key) ? 'Du' : nicks[k] || nameOf(k);
const convName = ck => isG(ck) ? (groups.get(gidOf(ck)) || {}).name || 'Gruppe' : display(ck);
function pubOf(k) { const f = friends.get(k); if (f) return f.pub; for (const g of groups.values()) { const m = g.members.find(x => x.key === k); if (m) return m.pub; } return null; }
const isBlocked = k => blocked.some(b => b.toLowerCase() === k);

// ---------- Verbindung zum Server
const waiters = [];
function waitFor(type, ms) {
  return new Promise((res, rej) => {
    const w = { type, res, rej };
    waiters.push(w);
    setTimeout(() => { const i = waiters.indexOf(w); if (i >= 0) { waiters.splice(i, 1); rej(new Error('Keine Antwort vom Server – bitte nochmal versuchen.')); } }, ms || 60000);
  });
}
function settle(type, val, err) {
  const i = waiters.findIndex(w => err ? true : w.type === type);
  if (i < 0) return false;
  const [w] = waiters.splice(i, 1);
  err ? w.rej(err) : w.res(val);
  return true;
}
const wsReady = () => ws && ws.readyState === 1;
function send(o) { if (wsReady()) { ws.send(JSON.stringify(o)); return true; } return false; }
function connect() {
  return new Promise((res, rej) => {
    if (wsReady()) return res();
    if (ws) { try { ws.onclose = null; ws.close(); } catch (e) {} }
    const s = ws = new WebSocket(SERVER);
    let opened = false;
    const slow = setTimeout(() => { if (!opened) status('Server wacht auf … das kann beim ersten Mal bis zu einer Minute dauern.'); }, 3500);
    s.onopen = () => { opened = true; clearTimeout(slow); retryN = 0; lastRx = Date.now(); res(); };
    s.onmessage = e => onRaw(e.data);
    s.onclose = () => {
      clearTimeout(slow);
      if (ws !== s) return;
      ws = null;
      while (waiters.length) waiters.shift().rej(new Error('Verbindung zum Server getrennt.'));
      if (!opened) rej(new Error('Keine Verbindung zum Server.'));
      onDisconnect();
    };
  });
}
// Kostenlose Server schlafen – bis zu ~90 s lang neu versuchen
async function connectRetry() {
  const t0 = Date.now();
  for (;;) {
    try { await connect(); return; } catch (e) {
      if (Date.now() - t0 > 90000) throw new Error('Der Chat-Server ist nicht erreichbar. Prüf dein Internet und versuch es gleich nochmal.');
      status('Server wacht auf … bitte kurz warten.');
      await sleep(3000);
    }
  }
}
function onDisconnect() {
  if (call && call.state === 'live') holdCall();
  else if (call) endCall(false, 'Verbindung getrennt');
  if (!me || manualClose) return;
  conn('Verbindung getrennt – verbinde neu …');
  clearTimeout(retryT);
  retryT = setTimeout(reconnect, Math.min(30000, 1500 * Math.pow(2, retryN++)));
}
async function reconnect() {
  if (!me || manualClose) return;
  try {
    await connect();
    pendingKeys = { auth: me.auth, wrapRaw: me.wrapRaw };
    send({ t: 'login', u: me.u, auth: me.auth, v: 2 });
  } catch (e) { onDisconnect(); }
}
// Nach Ruhezustand / Netzwechsel sofort neu verbinden statt auf den Zeitplan zu warten
window.addEventListener('online', () => { if (me && !wsReady()) { clearTimeout(retryT); reconnect(); } });
document.addEventListener('visibilitychange', () => {
  if (document.hidden || !me) return;
  if (!wsReady()) { clearTimeout(retryT); reconnect(); return; }
  // Zurück aus dem Hintergrund: lebt die Verbindung noch? Sonst nach 5 s neu verbinden (statt erst nach einer Minute)
  const t0 = Date.now(); send({ t: 'ping' });
  setTimeout(() => { if (me && wsReady() && lastRx < t0) { const s0 = ws; ws = null; s0.onclose = null; try { s0.close(); } catch (e) {} while (waiters.length) waiters.shift().rej(new Error('Verbindung zum Server getrennt.')); onDisconnect(); } }, 5000);
});
let lastRx = Date.now();
setInterval(() => {
  if (!wsReady() || !me) return;
  if (Date.now() - lastRx > 55000) {   // seit fast einer Minute nichts gehört → Verbindung hängt
    const s0 = ws; ws = null; s0.onclose = null; try { s0.close(); } catch (e) {}
    while (waiters.length) waiters.shift().rej(new Error('Verbindung zum Server getrennt.'));
    onDisconnect(); return;
  }
  send({ t: 'ping' });
}, 20000);
// Nachrichten nacheinander verarbeiten (Entschlüsseln ist asynchron, die Reihenfolge muss stimmen)
let chain = Promise.resolve();
function onRaw(data) {
  lastRx = Date.now();
  let m; try { m = JSON.parse(data); } catch (e) { return; }
  if (m.t === 'a') { onAudio(m); return; }
  if (m.t === 'pong') return;   // Ton nicht hinter andere Nachrichten einreihen
  chain = chain.then(() => handle(m)).catch(e => console.error(e));
}
async function handle(m) {
  switch (m.t) {
    case 'salt': settle('salt', m); return;
    case 'av': {
      if (typeof m.img !== 'string' || (m.img && !/^\/9j\/[A-Za-z0-9+/=]+$/.test(m.img))) return;
      const k = String(m.u).toLowerCase();
      if (m.img) avCache[k] = { v: m.v, img: m.img }; else delete avCache[k];
      lsSet('sparkchat.av', avCache);
      renderAll(); if (call) callUi();
      return;
    }
    case 'hello': {
      if (pendingKeys) { const k = pendingKeys; pendingKeys = null; try { await onHello(m, k); settle('hello', m); } catch (e) { settle('hello', null, e); } }
      else if (me) { me.invisible = !!m.me.invisible; renderMe(); }
      return;
    }
    case 'err': {
      if (waiters.length) { settle(null, null, Object.assign(new Error(m.msg), { auth: m.auth, retry: m.retry })); return; }
      if (pendingKeys) { pendingKeys = null; if (m.auth) return logout(m.msg); }
      if (m.fatal) return logout(m.msg);
      toast(m.msg);
      return;
    }
    case 'social': return onSocial(m);
    case 'pres': {
      const f = friends.get(String(m.u).toLowerCase()); if (!f) return;
      const was = f.on; f.on = !!m.on; f.act = m.act || ''; f.status = m.status || '';
      if (!was && f.on) { blip([660, 880], .06, .04); resendPending(f.key); }
      renderFriends(); if (sel === f.key) renderHead();
      return;
    }
    case 'pushok': pushOn = !!m.on; lsSet('sparkchat.push', pushOn); if ($('sPush')) $('sPush').classList.toggle('on', pushOn); if (m.on) toast('📱 Push-Benachrichtigungen sind an.', true); return;
    case 'mystatus': if (me) { me.status = m.text || ''; renderMe(); } return;
    case 'req': toast('🤝 ' + m.u + ' möchte dein Freund sein', true); notify('Freundschaftsanfrage', m.u + ' möchte dein Freund sein.'); blip([523, 784], .09); return;
    case 'info': toast(m.msg, !!m.ok); return;
    case 'gnew': if (groups.has(m.id)) openChat('g:' + m.id); else openAfter = 'g:' + m.id; return;
    case 'msg': return onDM(m);
    case 'gmsg': return onGroupMsg(m);
    case 'dlv': case 'queued': case 'nack': case 'gack': case 'sent': {
      const e = findMsg(m.id); if (!e) return;
      if (e.st === 'dlv' && m.t !== 'dlv') return;   // „zugestellt“ nicht wieder überschreiben
      e.st = m.t === 'dlv' ? 'dlv' : m.t === 'queued' ? 'wait' : (m.t === 'gack' || m.t === 'sent') ? 'sent' : 'fail';
      if (m.t === 'nack') toast(m.msg || 'Nachricht konnte nicht gesendet werden.');
      if (e.hidden && e.st !== 'fail' && e.st !== 'send') dropHidden(e);
      saveHist(e.ck); if (e.ck === sel) renderMsgs();
      return;
    }
    case 'typing': {
      const ck = m.g ? 'g:' + m.g : String(m.u).toLowerCase(), who = String(m.u).toLowerCase();
      typingT[ck] = typingT[ck] || {};
      clearTimeout(typingT[ck][who]); typingT[ck][who] = setTimeout(() => { delete typingT[ck][who]; renderTyping(); }, 4500);
      renderTyping(); return;
    }
    case 'call': return onCall(m);
    case 'pwok': return onPwOk(m);
    case 'mydata': return showMyData(m.data);
    case 'deleted': {
      const k = me && me.key;
      if (k) mediaDel(k + '|');
      if (k) for (const key of Object.keys(localStorage)) if (key.startsWith('sparkchat.h.' + k + '.') || key === 'sparkchat.pin.' + k || key === 'sparkchat.unread.' + k || key === 'sparkchat.nick.' + k) localStorage.removeItem(key);
      return logout('Dein Konto und alle Daten dazu wurden gelöscht.', true);
    }
  }
}

// ---------- Anmeldung
let regMode = false;
function setMode(reg) {
  regMode = reg;
  $('tabLogin').classList.toggle('on', !reg); $('tabReg').classList.toggle('on', reg);
  $('regOnly').hidden = !reg;
  $('authTitle').textContent = reg ? 'Konto erstellen' : 'Willkommen zurück';
  $('authSub').textContent = reg ? 'Wähle einen Benutzernamen – darüber finden dich deine Freunde.' : 'Melde dich an, um mit deinen Freunden zu schreiben und zu telefonieren.';
  $('authBtn').textContent = reg ? 'KONTO ERSTELLEN' : 'ANMELDEN';
  $('aPass').autocomplete = reg ? 'new-password' : 'current-password';
  authMsg('');
}
function authMsg(s, ok) { $('authMsg').textContent = s || ''; $('authMsg').className = 'msgline' + (ok ? ' ok' : ''); }
function status(s) { if (me) conn(s); else authMsg(s, true); }
$('tabLogin').onclick = () => setMode(false);
$('tabReg').onclick = () => setMode(true);
$('authForm').onsubmit = async e => {
  e.preventDefault();
  const u = $('aUser').value.trim(), pw = $('aPass').value;
  if (!NAME_RE.test(u)) return authMsg('Benutzername: 3–20 Zeichen, nur Buchstaben, Ziffern, _ . -');
  if (regMode) {
    if (pw.length < 8) return authMsg('Das Passwort braucht mindestens 8 Zeichen.');
    if (pw !== $('aPass2').value) return authMsg('Die Passwörter stimmen nicht überein.');
    if (!$('aAge').checked) return authMsg('Für SPARK Chat musst du mindestens 16 Jahre alt sein.');
    if (!$('aAgree').checked) return authMsg('Bitte akzeptiere die Nutzungsbedingungen und die Datenschutzerklärung.');
  } else if (!pw) return authMsg('Bitte Passwort eingeben.');
  $('authBtn').disabled = true;
  try {
    authMsg('Verbinde …', true);
    await connectRetry();
    stayLogged = $('aStay').checked;
    let salt;
    if (regMode) salt = hex(rnd(16));
    else { send({ t: 'salt', u }); salt = (await waitFor('salt')).salt; }
    authMsg('Schlüssel werden berechnet …', true);
    const keys = await deriveKeys(u, pw, salt);
    const helloP = waitFor('hello');
    pendingKeys = keys;
    if (regMode) {
      authMsg('Erstelle dein Schlüsselpaar …', true);
      const kp = await C.generateKey(ECDH, true, ['deriveBits']);
      const pub = b64(await C.exportKey('raw', kp.publicKey)), encPriv = await wrapPriv(kp.privateKey, keys.wrapRaw);
      send({ t: 'register', u, salt, auth: keys.auth, pub, encPriv, agree: true, v: 2 });
    } else send({ t: 'login', u, auth: keys.auth, v: 2 });
    await helloP;
    $('aPass').value = $('aPass2').value = '';
  } catch (err) {
    pendingKeys = null;
    authMsg(err.message);
  }
  $('authBtn').disabled = false;
};
async function onHello(m, keys) {
  const key = m.me.u.toLowerCase(), same = me && me.key === key;
  const priv = await unwrapPriv(m.me.encPriv, keys.wrapRaw);
  wantAv(m.me.u, m.me.av || 0);
  me = { u: m.me.u, key, auth: keys.auth, wrapRaw: keys.wrapRaw, priv, pub: m.me.pub, salt: m.me.salt, invisible: !!m.me.invisible, created: m.me.created, encPrivRaw: m.me.encPriv, status: m.me.status || '', vapid: m.me.vapid || '' };
  manualClose = false;
  if (!same) {
    shared.clear(); hist.clear(); friends.clear(); groups.clear(); sel = null;
    histKey = await hkdfKey(keys.wrapRaw, 'spark-chat/history/v1');
    pins = lsGet('sparkchat.pin.' + key, {});
    nicks = lsGet('sparkchat.nick.' + key, {});
    Object.assign(unread, lsGet('sparkchat.unread.' + key, {}));
    await loadHist();
    saveLogin();
    showApp();
  }
  conn('');
  renderMe();
  setTimeout(() => resendPending(), 400);
  setTimeout(syncPush, 800);
  if (call && call.state === 'live' && call.hold) { send({ t: 'call', op: 'resume', cid: call.cid }); call.hold = false; clearTimeout(call.holdT); callUi(); }
  const open = new URLSearchParams(location.search).get('c'); if (open && convExists(open)) openChat(open);
}
// Angemeldet bleiben: im SPARK-Launcher von Windows verschlüsselt, im Browser im Speicher dieses Geräts
// (nur wenn gewünscht – sonst nur bis der Tab geschlossen wird)
function saveLogin() {
  const d = JSON.stringify({ u: me.u, auth: me.auth, wrap: hex(me.wrapRaw) });
  clearLogin(true);
  if (stayLogged && SPARK && SPARK.vault) SPARK.vault.set('chat', d);
  else if (stayLogged) try { localStorage.setItem('sparkchat.keep', d); } catch (e) {}
  else try { sessionStorage.setItem('sparkchat.s', d); } catch (e) {}
}
function clearLogin(keepVault) {
  if (!keepVault && SPARK && SPARK.vault) SPARK.vault.del('chat');
  try { localStorage.removeItem('sparkchat.keep'); sessionStorage.removeItem('sparkchat.s'); } catch (e) {}
}
function showApp() {
  $('auth').hidden = true; $('app').hidden = false; renderAll(); updateActivity();
  if (canInstall() && matchMedia('(hover: none)').matches && !lsGet('sparkchat.installHint', false)) { lsSet('sparkchat.installHint', true); setTimeout(installApp, 1500); }
}
async function logout(msg, ok) {
  manualClose = true; clearTimeout(retryT);
  if (call) endCall(true);
  await pushOff(true);
  send({ t: 'logout' });
  try { if (ws) ws.close(); } catch (e) {}
  ws = null; me = null; histKey = null; friends.clear(); groups.clear(); hist.clear(); shared.clear(); sel = null;
  for (const k of Object.keys(unread)) delete unread[k];
  clearLogin();
  closeModal();
  $('app').hidden = true; $('auth').hidden = false; setMode(false);
  if (msg) authMsg(msg, ok);
  document.title = 'SPARK Chat';
}
// Gespeicherte Anmeldung
async function autoLogin() {
  let saved = null;
  try { saved = SPARK && SPARK.vault ? await SPARK.vault.get('chat') : null; } catch (e) {}
  if (saved) stayLogged = true;
  if (!saved) try { saved = sessionStorage.getItem('sparkchat.s'); } catch (e) {}
  if (!saved) try { saved = localStorage.getItem('sparkchat.keep'); if (saved) stayLogged = true; } catch (e) {}
  if (!saved) return;
  let d; try { d = JSON.parse(saved); } catch (e) { return; }
  $('aUser').value = d.u || '';
  $('authBtn').disabled = true;
  for (let tries = 0; tries < 6; tries++) {
    try {
      authMsg('Melde an …', true);
      await connectRetry();
      const helloP = waitFor('hello');
      pendingKeys = { auth: d.auth, wrapRaw: unhex(d.wrap) };
      send({ t: 'login', u: d.u, auth: d.auth, v: 2 });
      await helloP;
      break;
    } catch (err) {
      pendingKeys = null;
      if (err.auth) { clearLogin(); authMsg(err.message + ' Bitte neu anmelden.'); break; }
      authMsg(err.message);
      await sleep(err.retry ? 8000 : 15000);   // z. B. beim Windows-Start noch kein Internet
    }
  }
  $('authBtn').disabled = false;
}

// ---------- Freunde & Gruppen
function onSocial(m) {
  const old = friends; friends = new Map();
  for (const f of m.friends) {
    const key = f.u.toLowerCase(), o = old.get(key);
    const e = { key, u: f.u, pub: f.pub, on: f.on, act: f.act || '', status: f.status || '', warn: false, av: f.av || 0 };
    wantAv(f.u, e.av);
    if (o && o.pub === f.pub) e.warn = o.warn;
    if (!pins[key]) pins[key] = f.pub;
    else if (pins[key] !== f.pub) e.warn = true;
    friends.set(key, e);
    if (o && !o.on && e.on) resendPending(key);
  }
  lsSet('sparkchat.pin.' + me.key, pins);
  // Gruppen: Änderungen an den Mitgliedern als Hinweis im Verlauf
  const oldG = groups; groups = new Map();
  for (const g of m.groups || []) {
    const e = { id: g.id, name: g.name, owner: String(g.owner || '').toLowerCase(), members: g.members.map(x => ({ u: x.u, key: x.u.toLowerCase(), pub: x.pub, av: x.av || 0 })) };
    groups.set(g.id, e);
    for (const x of e.members) if (x.key !== me.key && !friends.has(x.key)) wantAv(x.u, x.av);
    const o = oldG.get(g.id);
    if (o) {
      const ck = 'g:' + g.id, was = new Set(o.members.map(x => x.key)), now = new Set(e.members.map(x => x.key));
      for (const x of e.members) if (!was.has(x.key)) sysMsg(ck, x.u + ' ist der Gruppe beigetreten');
      for (const x of o.members) if (!now.has(x.key)) sysMsg(ck, x.u + ' hat die Gruppe verlassen');
      if (o.name !== e.name) sysMsg(ck, 'Gruppe umbenannt in „' + e.name + '“');
    } else if (oldG.size || m.fresh) sysMsg('g:' + g.id, 'Du bist jetzt in der Gruppe „' + e.name + '“');
    for (const x of e.members) if (shared.has(x.key) && shared.get(x.key).pub !== x.pub) shared.delete(x.key);
  }
  inReq = m.inReq; outReq = m.outReq; blocked = m.blocked;
  if (sel && !convExists(sel)) sel = null;
  if (openAfter && convExists(openAfter)) { const ck = openAfter; openAfter = null; openChat(ck); return; }
  renderAll();
}
const convExists = ck => isG(ck) ? groups.has(gidOf(ck)) : friends.has(ck);
function sysMsg(ck, text) { pushHist(ck, { id: rid(), from: me.key, me: true, k: 'sys', text, ts: Date.now(), st: 'dlv', ck }); if (ck === sel) renderMsgs(); }
$('addForm').onsubmit = e => {
  e.preventDefault();
  const u = $('addName').value.trim();
  if (!NAME_RE.test(u)) return toast('Gib den genauen Benutzernamen deines Freundes ein.');
  if (me && u.toLowerCase() === me.key) return toast('Das bist du selbst 🙂');
  send({ t: 'freq', u }); $('addName').value = '';
};
const hue = s => { let h = 0; for (const c of String(s).toLowerCase()) h = (h * 31 + c.charCodeAt(0)) % 360; return h; };
// Profilbilder: nur Freunde (und Gruppen-Mitglieder) bekommen sie vom Server; hier zwischengespeichert
let avCache = lsGet('sparkchat.av', {});
const avImg = s => { const a = avCache[String(s).toLowerCase()]; return a && a.img ? a.img : ''; };
const avStyle = s => avImg(s) ? 'background:#111 url(data:image/jpeg;base64,' + avImg(s) + ') center/cover' : 'background:linear-gradient(135deg,hsl(' + hue(s) + ',95%,68%),hsl(' + ((hue(s) + 40) % 360) + ',90%,52%))';
const avLetter = s => avImg(s) ? '' : esc(String(s)[0].toUpperCase());
const avHtml = (s, extra) => '<div class="avw"><div class="av" style="' + avStyle(s) + '">' + avLetter(s) + '</div>' + (extra || '') + '</div>';
const grpAv = g => '<div class="avw"><div class="av grp" style="background:linear-gradient(135deg,hsl(' + hue(g.id) + ',70%,60%),hsl(' + ((hue(g.id) + 70) % 360) + ',80%,45%))">👥</div></div>';
function setAv(el, s) { el.innerHTML = avLetter(s); el.setAttribute('style', avStyle(s)); el.className = 'av'; }
function wantAv(name, v) {
  const k = String(name).toLowerCase(), c = avCache[k];
  if (!v) { if (c) { delete avCache[k]; lsSet('sparkchat.av', avCache); } return; }
  if (!c || c.v !== v) send({ t: 'getav', u: name });
}
function stOf(f) { return !f.on ? ['Offline', ''] : f.act ? [f.act, 'play'] : [f.status ? '● ' + f.status : 'Online', 'on']; }
function lastTs(k) { const h = hist.get(k); if (!h) return 0; for (let i = h.length - 1; i >= 0; i--) if (!h[i].hidden) return h[i].ts; return 0; }
function lastLine(ck) {
  const h = hist.get(ck); if (!h) return '';
  for (let i = h.length - 1; i >= 0; i--) { const e = h[i]; if (e.hidden) continue; return (isG(ck) && e.k !== 'sys' ? display(e.from) + ': ' : '') + preview(e); }
  return '';
}
const preview = e => e.del ? 'Nachricht gelöscht' : e.k === 'img' ? '📷 Bild' : e.k === 'voice' ? '🎤 Sprachnachricht' : e.k === 'inv' ? '🎮 Einladung' : e.text || '';
function renderFriends() {
  const list = [...friends.values()].sort((a, b) => (b.on - a.on) || (lastTs(b.key) - lastTs(a.key)) || display(a.key).localeCompare(display(b.key)));
  $('frCount').textContent = list.filter(f => f.on).length + ' / ' + list.length + ' online';
  $('friends').innerHTML = list.length ? list.map(f => {
    const [st, cls] = stOf(f), n = unread[f.key] || 0, nick = nicks[f.key];
    return '<button class="fr' + (f.key === sel ? ' sel' : '') + '" data-k="' + esc(f.key) + '">' + avHtml(f.u, '<div class="pd ' + cls + '"></div>') +
      '<div class="meta"><div class="nm">' + esc(nick || f.u) + (nick ? ' <small>' + esc(f.u) + '</small>' : '') + (f.warn ? ' ⚠' : '') + '</div><div class="st ' + cls + '">' + esc(st) + '</div></div>' + (n ? '<div class="unread">' + (n > 99 ? '99+' : n) + '</div>' : '') + '</button>';
  }).join('') : '<div class="empty-side">Noch keine Freunde.<br>Gib oben den Benutzernamen eines Freundes ein.</div>';
  const gl = [...groups.values()].sort((a, b) => lastTs('g:' + b.id) - lastTs('g:' + a.id) || a.name.localeCompare(b.name));
  $('groups').innerHTML = gl.length ? gl.map(g => {
    const ck = 'g:' + g.id, n = unread[ck] || 0;
    return '<button class="fr' + (ck === sel ? ' sel' : '') + '" data-k="' + esc(ck) + '">' + grpAv(g) + '<div class="meta"><div class="nm">' + esc(g.name) + '</div><div class="st">' + esc(lastLine(ck) || g.members.length + ' Mitglieder') + '</div></div>' + (n ? '<div class="unread">' + (n > 99 ? '99+' : n) + '</div>' : '') + '</button>';
  }).join('') : '<div class="empty-side">Noch keine Gruppen.</div>';
  for (const b of document.querySelectorAll('#friends .fr, #groups .fr')) b.onclick = () => openChat(b.dataset.k);
  let rq = '';
  if (inReq.length) rq += '<div class="label sect" style="color:var(--amber)">Anfragen · ' + inReq.length + '</div>' + inReq.map(u => '<div class="req">' + avHtml(u) + '<div class="nm">' + esc(u) + '</div><button class="ico yes" data-yes="' + esc(u) + '" title="Annehmen">✔</button><button class="ico no" data-no="' + esc(u) + '" title="Ablehnen">✖</button></div>').join('');
  if (outReq.length) rq += '<div class="label sect">Gesendet · ' + outReq.length + '</div>' + outReq.map(u => '<div class="req">' + avHtml(u) + '<div class="nm" style="color:var(--dim)">' + esc(u) + '</div><button class="ico no" data-cancel="' + esc(u) + '" title="Anfrage zurückziehen">✖</button></div>').join('');
  $('reqBox').innerHTML = rq;
  for (const b of $('reqBox').querySelectorAll('[data-yes]')) b.onclick = () => send({ t: 'fans', u: b.dataset.yes, yes: true });
  for (const b of $('reqBox').querySelectorAll('[data-no]')) b.onclick = () => send({ t: 'fans', u: b.dataset.no, yes: false });
  for (const b of $('reqBox').querySelectorAll('[data-cancel]')) b.onclick = () => send({ t: 'fcancel', u: b.dataset.cancel });
  const total = Object.values(unread).reduce((s, n) => s + n, 0);
  document.title = (total ? '(' + total + ') ' : '') + 'SPARK Chat';
  if (SPARK && SPARK.badge) SPARK.badge(total);
}
function renderMe() {
  if (!me) return;
  $('meName').textContent = me.u;
  setAv($('meAv'), me.u);
  $('meSt').textContent = me.invisible ? 'Unsichtbar' : actNow || (me.status ? '● ' + me.status : 'Online') ;
  $('meSt').style.color = me.invisible ? 'var(--faint)' : actNow ? 'var(--amber)' : '';
  $('mePd').className = 'pd ' + (me.invisible ? '' : actNow ? 'play' : 'on');
}
function renderAll() { renderMe(); renderFriends(); renderChat(); }
$('meMeta').onclick = () => editStatus();
function editStatus() {
  openModal('<span class="label">// Dein Status</span><h2>💬 STATUS<span>TEXT</span></h2><p class="hint">Sehen nur deine Freunde, solange du online bist.</p>' +
    '<label class="field"><span>Status (max. 60 Zeichen)</span><input class="inp" id="stIn" maxlength="60" placeholder="z. B. In der Schule · Zocke gleich BLACKOUT" value="' + esc(me.status || '') + '"></label>' +
    '<div class="seg" style="margin-bottom:12px">' + ['🎮 Zocke gerade', '📚 Hausaufgaben', '🏫 In der Schule', '😴 Schlafe', '🎧 Nicht stören'].map(s => '<button data-st="' + esc(s) + '">' + esc(s) + '</button>').join('') + '</div>' +
    '<div class="btnrow"><button class="btn cy" id="stOk">SPEICHERN</button><button class="sec" id="stClr">Status löschen</button></div>');
  for (const b of $('sheet').querySelectorAll('[data-st]')) b.onclick = () => { $('stIn').value = b.dataset.st; };
  $('stOk').onclick = () => { send({ t: 'status', text: $('stIn').value.trim() }); closeModal(); };
  $('stClr').onclick = () => { send({ t: 'status', text: '' }); closeModal(); };
  setTimeout(() => $('stIn').focus(), 50);
}

// ---------- Chat-Ansicht
function openChat(k) {
  if (call && call.state === 'live' && call.fk !== k && !callMini) { callMini = true; callUi(); }
  sel = k; unread[k] = 0; lsSet('sparkchat.unread.' + me.key, unread);
  cancelReply();
  $('app').classList.add('chatting');
  renderFriends(); renderChat();
  if (!matchMedia('(hover: none)').matches) setTimeout(() => $('text').focus(), 0);
}
function goBack() { sel = null; $('app').classList.remove('chatting'); if (call && call.state === 'live' && !callMini) { callMini = true; callUi(); } renderFriends(); renderChat(); }
$('back').onclick = goBack;
// Handy: im Chat nach rechts wischen → zurück zur Kontaktliste
(() => {
  let sx = 0, sy = 0, st = 0;
  $('chat').addEventListener('touchstart', e => { const t = e.touches[0]; sx = t.clientX; sy = t.clientY; st = Date.now(); }, { passive: true });
  $('chat').addEventListener('touchend', e => {
    const t = e.changedTouches[0], dx = t.clientX - sx, dy = Math.abs(t.clientY - sy);
    if (innerWidth <= 720 && dx > 80 && dy < 60 && Date.now() - st < 700 && sx < innerWidth * 0.7) goBack();
  }, { passive: true });
})();
function renderChat() {
  const ok = sel && convExists(sel);
  $('welcome').hidden = !!ok; $('chat').hidden = !ok;
  if (!ok) return;
  renderHead(); renderMsgs(); renderTyping();
}
function renderHead() {
  if (!sel) return;
  $('cInvite').hidden = false;
  if (isG(sel)) {
    const g = groups.get(gidOf(sel)); if (!g) return;
    $('cName').textContent = g.name;
    const el = $('cAv'); el.className = 'av grp'; el.textContent = '👥'; el.setAttribute('style', 'background:linear-gradient(135deg,hsl(' + hue(g.id) + ',70%,60%),hsl(' + ((hue(g.id) + 70) % 360) + ',80%,45%))');
    $('cPd').className = 'pd none';
    $('cSt').textContent = g.members.length + ' Mitglieder · ' + g.members.map(x => display(x.key)).join(', '); $('cSt').className = 'st';
    $('cCall').hidden = true; $('keyWarn').hidden = true;
    return;
  }
  const f = friends.get(sel); if (!f) return;
  const [st, cls] = stOf(f);
  $('cName').textContent = display(f.key);
  setAv($('cAv'), f.u);
  $('cPd').className = 'pd ' + cls;
  $('cSt').textContent = (nicks[f.key] ? f.u + ' · ' : '') + st; $('cSt').className = 'st ' + cls;
  $('cCall').hidden = false;
  $('cCall').disabled = !f.on || (!!call && call.state !== 'end');
  $('cCall').title = f.on ? 'Sprachanruf' : f.u + ' ist offline';
  $('keyWarn').hidden = !f.warn;
  if (f.warn) {
    $('keyWarn').innerHTML = '⚠ <b>Der Sicherheitsschlüssel von ' + esc(f.u) + ' hat sich geändert.</b> Das passiert, wenn das Konto gelöscht und neu erstellt wurde. Frag ' + esc(f.u) + ' persönlich, ob das stimmt, und vergleicht die Sicherheitsnummer. <button class="sec" id="keyOk" style="height:30px;margin-left:8px">Neuen Schlüssel bestätigen</button>';
    $('keyOk').onclick = () => { pins[f.key] = f.pub; lsSet('sparkchat.pin.' + me.key, pins); f.warn = false; renderHead(); renderFriends(); };
  }
}
$('cMeta').onclick = () => { if (sel && isG(sel)) showGroup(gidOf(sel)); else if (sel) showFriend(sel); };
const linkify = s => esc(s).replace(/\bhttps?:\/\/[^\s<>&]+(?:&amp;[^\s<>&]+)*/g, u => '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + u + '</a>');
const hm = ts => new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
function dayLabel(ts) {
  const d = new Date(ts), t = new Date(); t.setHours(0, 0, 0, 0);
  const diff = Math.round((t - new Date(d.getFullYear(), d.getMonth(), d.getDate())) / 864e5);
  return diff === 0 ? 'HEUTE' : diff === 1 ? 'GESTERN' : d.toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric' }).toUpperCase();
}
const ST_ICON = { send: ['s-wait', '◌'], wait: ['s-wait', '⏳'], sent: ['s-dlv', '✓'], dlv: ['s-dlv', '✓✓'], fail: ['s-fail', '✖ nicht gesendet'] };
const stHtml = e => e.me ? ' <span class="' + ST_ICON[e.st || 'dlv'][0] + '" title="' + ({ send: 'wird gesendet', wait: 'wartet – Empfänger offline', sent: 'gesendet', dlv: 'zugestellt', fail: 'nicht gesendet' }[e.st || 'dlv']) + '">' + ST_ICON[e.st || 'dlv'][1] + '</span>' : '';
const fmtDur = s => Math.floor(s / 60) + ':' + String(Math.floor(s % 60)).padStart(2, '0');
function renderMsgs() {
  if (!sel || !convExists(sel)) return;
  const group = isG(sel), box = $('msgs'), atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  const h = hist.get(sel) || [];
  let out = '<div class="e2e">🔒 ' + (group ? 'Nachrichten in dieser Gruppe' : 'Nachrichten und Anrufe mit ' + esc(convName(sel))) + ' sind Ende-zu-Ende-verschlüsselt. Der Verlauf liegt nur auf deinen Geräten.</div>', lastDay = '', last = null;
  for (const e of h) {
    if (e.hidden) continue;
    const d = dayLabel(e.ts); if (d !== lastDay) { out += '<div class="day">' + d + '</div>'; lastDay = d; last = null; }
    if (e.k === 'sys') { out += '<div class="sysm">' + esc(e.text) + ' · ' + hm(e.ts) + '</div>'; last = null; continue; }
    if (e.k === 'inv' && !e.del) {
      const old = Date.now() - e.ts > 3 * 3600e3;
      out += '<div class="inv' + (e.me ? ' mine' : '') + '"><span class="label">// Einladung · BLACKOUT</span><b>' + (e.me ? 'Du hast eingeladen' : esc(display(e.from)) + ' lädt dich ein') + '</b><div class="code">RAUM ' + esc(e.code) + '</div>' +
        (!e.me ? '<button class="btn ok" data-join="' + esc(e.code) + '"' + (old ? ' disabled title="Einladung ist abgelaufen"' : '') + '>' + (old ? 'ABGELAUFEN' : '▶ BEITRETEN') + '</button>' : '') +
        '<span class="tm">' + hm(e.ts) + stHtml(e) + '</span></div>';
      last = null; continue;
    }
    const gap = !last || last.from !== e.from || e.ts - last.ts > 5 * 60000;
    let body = '';
    if (e.re && !e.del) body += '<span class="quote" data-goto="' + esc(e.re.id) + '"><b>' + esc(e.re.from === me.u ? 'Du' : display(String(e.re.from).toLowerCase())) + '</b>: ' + esc(e.re.snip) + '</span>';
    let cls = 'm';
    if (e.del) { cls += ' del'; body += '🚫 Nachricht gelöscht'; }
    else if (e.k === 'img') { cls += ' pic'; const w = Math.min(300, e.w || 300); body += '<img data-media="' + esc(e.id) + '" alt="Bild" style="width:' + w + 'px;aspect-ratio:' + (e.w || 3) + '/' + (e.h || 2) + '">'; }
    else if (e.k === 'voice') body += '<div class="voice" data-voice="' + esc(e.id) + '" data-mime="' + esc(e.mime || '') + '"><button class="play">▶</button><div class="vbar"><i></i></div><span class="vt">' + fmtDur(e.dur || 0) + '</span></div>';
    else body += linkify(e.text) + (e.edited ? ' <small style="color:var(--faint)">(bearbeitet)</small>' : '');
    const rx = e.rx ? Object.entries(e.rx) : [];
    let rxHtml = '';
    if (rx.length && !e.del) { const cnt = {}; for (const [, em] of rx) cnt[em] = (cnt[em] || 0) + 1; rxHtml = '<div class="rx">' + Object.entries(cnt).map(([em, n]) => '<span class="' + (e.rx[me.key] === em ? 'mine' : '') + '" title="' + esc(rx.filter(([, x]) => x === em).map(([k]) => display(k)).join(', ')) + '">' + em + (n > 1 ? ' ' + n : '') + '</span>').join('') + '</div>'; }
    const acts = e.del ? '' : '<div class="acts"><button data-a="react" title="Reagieren">😀</button><button data-a="reply" title="Antworten">↩</button>' + (e.me && e.k === 'text' ? '<button data-a="edit" title="Bearbeiten">✎</button>' : '') + '<button data-a="del" title="Löschen">🗑</button></div>';
    out += '<div class="mw' + (e.me ? ' mine' : '') + (gap ? ' gap' : '') + '" data-id="' + esc(e.id) + '">' + (group && !e.me && gap ? '<div class="who" style="color:hsl(' + hue(e.from) + ',75%,' + (document.documentElement.dataset.theme === 'light' ? '38%' : '65%') + ')">' + esc(display(e.from)) + '</div>' : '') +
      '<div class="' + cls + '">' + body + '<span class="tm">' + hm(e.ts) + stHtml(e) + '</span></div>' + rxHtml + acts + '</div>';
    last = e;
  }
  box.innerHTML = out;
  const ck = sel;
  for (const b of box.querySelectorAll('[data-join]')) b.onclick = () => joinGame(b.dataset.join);
  for (const im of box.querySelectorAll('img[data-media]')) {
    mediaUrl(ck, im.dataset.media, 'image/jpeg').then(u => { if (u) { im.src = u; im.onload = () => { if (atBottom || box.dataset.for !== ck) box.scrollTop = box.scrollHeight; }; } else im.alt = 'Bild nicht mehr vorhanden'; });
    im.onclick = () => im.src && showImage(im.src);
  }
  for (const v of box.querySelectorAll('[data-voice]')) v.querySelector('.play').onclick = () => playVoice(ck, v);
  for (const q of box.querySelectorAll('[data-goto]')) q.onclick = () => { const t = box.querySelector('.mw[data-id="' + CSS.escape(q.dataset.goto) + '"]'); if (t) { t.scrollIntoView({ block: 'center', behavior: 'smooth' }); t.classList.add('flash'); setTimeout(() => t.classList.remove('flash'), 1300); } };
  for (const w of box.querySelectorAll('.mw')) {
    w.onclick = ev => { if (matchMedia('(hover: none)').matches && !ev.target.closest('button,a,img,.acts')) { for (const o of box.querySelectorAll('.mw.act')) if (o !== w) o.classList.remove('act'); w.classList.toggle('act'); } };
    for (const b of w.querySelectorAll('.acts button')) b.onclick = ev => { ev.stopPropagation(); msgAction(ck, w.dataset.id, b.dataset.a, b); };
  }
  if (atBottom || box.dataset.for !== sel) box.scrollTop = box.scrollHeight;
  box.dataset.for = sel;
}
function renderTyping() {
  const t = sel && typingT[sel] ? Object.keys(typingT[sel]) : [];
  $('typing').textContent = t.length ? t.map(display).join(', ') + (t.length > 1 ? ' schreiben …' : ' schreibt …') : '';
}

// ---------- Aktionen an Nachrichten: Reagieren, Antworten, Bearbeiten, Löschen
function msgAction(ck, id, a, btn) {
  const e = (hist.get(ck) || []).find(x => x.id === id); if (!e) return;
  if (a === 'react') {
    const m = $('menu'); m.className = 'menu emoji';
    m.innerHTML = REACTS.map(r => '<button data-r="' + r + '"' + (e.rx && e.rx[me.key] === r ? ' style="background:var(--acc-a)"' : '') + '>' + r + '</button>').join('');
    m.hidden = false; placeMenu(m, btn);
    for (const b of m.querySelectorAll('button')) b.onclick = () => { m.hidden = true; const r = e.rx && e.rx[me.key] === b.dataset.r ? '' : b.dataset.r; applyReact(e, me.key, r); sendControl(ck, { k: 'react', to: id, e: r }); };
  } else if (a === 'reply') {
    replyTo = { id: e.id, from: e.me ? me.u : nameOf(e.from), snip: preview(e).slice(0, 80) }; editId = null;
    $('replyBar').hidden = false; $('replyTxt').innerHTML = '↩ Antwort an <b>' + esc(e.me ? 'dich' : display(e.from)) + '</b>: ' + esc(replyTo.snip); $('text').focus();
  } else if (a === 'edit') {
    editId = e.id; replyTo = null;
    $('replyBar').hidden = false; $('replyTxt').innerHTML = '✎ <b>Nachricht bearbeiten</b>'; $('text').value = e.text; $('text').focus(); autosize();
  } else if (a === 'del') {
    const items = [];
    if (e.me && Date.now() - e.ts < 7 * 864e5) items.push({ label: '🗑 Für alle löschen', danger: true, fn: () => { applyDel(ck, e); sendControl(ck, { k: 'del', to: id }); } });
    items.push({ label: '🙈 Nur für mich löschen', fn: () => { const h = hist.get(ck); h.splice(h.indexOf(e), 1); if (e.k === 'img' || e.k === 'voice') mediaDel(me.key + '|' + ck + '|' + e.id); saveHist(ck); renderMsgs(); } });
    showMenu(btn, items);
  }
}
function cancelReply() { replyTo = null; editId = null; $('replyBar').hidden = true; }
$('replyX').onclick = () => { if (editId) $('text').value = ''; cancelReply(); };
function applyReact(e, who, r) { e.rx = e.rx || {}; if (r) e.rx[who] = r; else delete e.rx[who]; if (!Object.keys(e.rx).length) delete e.rx; saveHist(e.ck); if (e.ck === sel) renderMsgs(); }
function applyDel(ck, e) { e.del = true; delete e.text; delete e.rx; delete e.re; if (e.k === 'img' || e.k === 'voice') mediaDel(me.key + '|' + ck + '|' + e.id); saveHist(ck); if (ck === sel) renderMsgs(); renderFriends(); }

// ---------- Schreiben & Senden
function autosize() { const t = $('text'); t.style.height = 'auto'; t.style.height = Math.min(160, t.scrollHeight + 2) + 'px'; }
$('text').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && !matchMedia('(hover: none)').matches) { e.preventDefault(); $('compose').requestSubmit(); }
  if (e.key === 'Escape' && !$('replyBar').hidden) cancelReply();
  if (e.key === 'ArrowUp' && !$('text').value && sel) { const h = hist.get(sel) || []; for (let i = h.length - 1; i >= 0; i--) if (h[i].me && h[i].k === 'text' && !h[i].del && !h[i].hidden) { msgAction(sel, h[i].id, 'edit'); e.preventDefault(); break; } }
});
$('text').addEventListener('input', () => {
  autosize();
  if (!sel || Date.now() - lastTyping < 3000) return;
  lastTyping = Date.now();
  if (isG(sel)) send({ t: 'gtyping', g: gidOf(sel) }); else { const f = friends.get(sel); if (f && f.on) send({ t: 'typing', u: f.u }); }
});
$('compose').onsubmit = e => {
  e.preventDefault();
  const text = $('text').value.trim();
  if (!sel) return;
  if (!text) return;
  if (text.length > 4000) return toast('Die Nachricht ist zu lang (max. 4000 Zeichen).');
  $('text').value = ''; autosize(); lastTyping = 0;
  if (editId) {
    const t = (hist.get(sel) || []).find(x => x.id === editId);
    if (t && t.text !== text) { t.text = text; t.edited = true; saveHist(sel); sendControl(sel, { k: 'edit', to: editId, text }); renderMsgs(); }
    cancelReply(); return;
  }
  const body = { k: 'text', text };
  if (replyTo) body.re = replyTo;
  cancelReply();
  sendMsg(sel, body);
};
const rid = () => hex(rnd(9));
function sendMsg(ck, body, id) {
  const e = Object.assign({ id: id || rid(), from: me.key, me: true, ts: Date.now(), st: 'send', ck }, body);
  pushHist(ck, e);
  transmit(ck, e);
  if (ck === sel) renderMsgs();
  renderFriends();
}
// Steuer-Nachrichten (Reaktion, Löschen, Bearbeiten) werden unsichtbar gemerkt, bis sie angekommen sind
function sendControl(ck, body) {
  const e = { id: rid(), from: me.key, me: true, ts: Date.now(), st: 'send', ck, hidden: true, body };
  pushHist(ck, e); transmit(ck, e);
}
function dropHidden(e) { const h = hist.get(e.ck); if (h) { const i = h.indexOf(e); if (i >= 0) h.splice(i, 1); } }
async function bodyOf(ck, e) {
  if (e.hidden) return e.body;
  if (e.k === 'inv') return { k: 'inv', game: e.game, code: e.code };
  if (e.k === 'img' || e.k === 'voice') {
    const bytes = await mediaGet(ck, e.id); if (!bytes) throw new Error('Datei fehlt');
    return e.k === 'img' ? { k: 'img', data: b64(bytes), w: e.w, h: e.h, re: e.re } : { k: 'voice', data: b64(bytes), mime: e.mime, dur: e.dur, re: e.re };
  }
  return { k: 'text', text: e.text, re: e.re };
}
async function transmit(ck, e) {
  if (!wsReady() || !convExists(ck)) return;
  try {
    const plain = te.encode(JSON.stringify(await bodyOf(ck, e)));
    if (isG(ck)) {
      const g = groups.get(gidOf(ck)), K = rnd(32), keys = {};
      const ct = await encWith(await aesKey(K), plain, 'g:' + g.id + '|' + me.key + '|' + e.id);
      for (const m of g.members) {
        if (m.key === me.key) continue;
        const s = await sharedFor(m.key, m.pub);
        keys[m.u] = b64(await encWith(s.msgKey, K, 'gk:' + g.id + '|' + me.key + '>' + m.key + '|' + e.id));
      }
      send({ t: 'gmsg', g: g.id, id: e.id, ct: b64(ct), keys });
    } else {
      const f = friends.get(ck);
      const ct = await encWith((await sharedFor(ck, f.pub)).msgKey, plain, me.key + '>' + ck + '|' + e.id);
      send({ t: 'msg', u: f.u, id: e.id, iv: b64(ct.subarray(0, 12)), ct: b64(ct.subarray(12)) });
    }
  } catch (err) { console.warn(err); e.st = 'fail'; saveHist(ck); if (ck === sel) renderMsgs(); }
}
// Noch nicht zugestellte Nachrichten erneut senden (nach Neuverbindung oder wenn ein Freund online kommt)
function resendPending(only) {
  const cut = Date.now() - 6 * 864e5;
  for (const [ck, h] of hist) {
    if (only && ck !== only) continue;
    if (!convExists(ck)) continue;
    for (const e of h.slice()) if (e.me && (e.st === 'send' || (e.st === 'wait' && !isG(ck))) && e.ts > cut && e.k !== 'sys') transmit(ck, e);
  }
}
// Empfangsbestätigung an den Server – erst dann gilt eine Nachricht als zugestellt
let gotList = [], gotT = null;
function ackGot(from, id) { gotList.push([from, id]); if (!gotT) gotT = setTimeout(() => { gotT = null; if (gotList.length && send({ t: 'got', items: gotList })) gotList = []; }, 250); }
async function onDM(m) {
  ackGot(m.from, m.id);
  const fk = String(m.from).toLowerCase(), f = friends.get(fk);
  if (!f || !me) return;
  let body;
  try { body = JSON.parse(td.decode(await decWith((await sharedFor(fk, f.pub)).msgKey, cat(unb64(m.iv), unb64(m.ct)), fk + '>' + me.key + '|' + m.id))); }
  catch (e) { body = { k: 'sys', text: '⚠ Eine Nachricht von ' + f.u + ' konnte nicht entschlüsselt werden' }; }
  await receive(fk, fk, m.id, m.ts, body);
}
async function onGroupMsg(m) {
  ackGot(m.from, m.id);
  const g = groups.get(m.g), fk = String(m.from).toLowerCase();
  if (!g || !me || isBlocked(fk)) return;
  const mem = g.members.find(x => x.key === fk);
  let body;
  try {
    if (!mem) throw new Error('kein Mitglied');
    const s = await sharedFor(fk, mem.pub);
    const K = await decWith(s.msgKey, unb64(m.k), 'gk:' + g.id + '|' + fk + '>' + me.key + '|' + m.id);
    body = JSON.parse(td.decode(await decWith(await aesKey(K), unb64(m.ct), 'g:' + g.id + '|' + fk + '|' + m.id)));
  } catch (e) { body = { k: 'sys', text: '⚠ Eine Nachricht von ' + m.from + ' konnte nicht entschlüsselt werden' }; }
  await receive('g:' + g.id, fk, m.id, m.ts, body);
}
async function receive(ck, fk, id, ts, body) {
  const h = hist.get(ck) || [];
  if (h.some(e => e.id === id)) return;   // doppelt (z. B. nach Neuverbindung)
  // Steuer-Nachrichten betreffen eine vorhandene Nachricht desselben Absenders
  if (body.k === 'react' || body.k === 'del' || body.k === 'edit') {
    const t = h.find(x => x.id === body.to); if (!t) return;
    if (body.k === 'react') return applyReact(t, fk, REACTS.includes(body.e) ? body.e : '');
    if (t.from !== fk) return;
    if (body.k === 'del') return applyDel(ck, t);
    if (t.k === 'text' && !t.del) { t.text = String(body.text || '').slice(0, 4000); t.edited = true; saveHist(ck); if (ck === sel) renderMsgs(); }
    return;
  }
  const e = { id, from: fk, me: false, ts: Math.min(Date.now(), ts || Date.now()), ck };
  const re = body.re && typeof body.re === 'object' ? { id: String(body.re.id || '').slice(0, 40), from: String(body.re.from || '').slice(0, 20), snip: String(body.re.snip || '').slice(0, 80) } : null;
  if (body.k === 'inv' && /^[A-Z0-9]{3,8}$/.test(body.code || '')) Object.assign(e, { k: 'inv', game: 'blackout', code: body.code });
  else if (body.k === 'sys') Object.assign(e, { k: 'sys', text: body.text });
  else if ((body.k === 'img' || body.k === 'voice') && typeof body.data === 'string') {
    const bytes = unb64(body.data);
    const okImg = body.k === 'img' && bytes[0] === 0xff && bytes[1] === 0xd8, okVoice = body.k === 'voice' && /^audio\/(webm|mp4|ogg|mpeg)/.test(body.mime || '');
    if (bytes.length > MAX_MEDIA * 1.1 || !(okImg || okVoice)) Object.assign(e, { k: 'sys', text: '⚠ Ungültige Datei von ' + display(fk) + ' verworfen' });
    else {
      await mediaPut(ck, id, bytes);
      if (body.k === 'img') Object.assign(e, { k: 'img', w: Math.min(4000, body.w | 0), h: Math.min(4000, body.h | 0) });
      else Object.assign(e, { k: 'voice', mime: String(body.mime).slice(0, 40), dur: Math.min(600, +body.dur || 0) });
    }
  }
  else Object.assign(e, { k: 'text', text: String(body.text || '').slice(0, 4000) });
  if (re && e.k !== 'sys') e.re = re;
  pushHist(ck, e);
  const seen = sel === ck && document.hasFocus() && !$('app').hidden && !document.hidden;
  if (!seen) { unread[ck] = (unread[ck] || 0) + 1; lsSet('sparkchat.unread.' + me.key, unread); }
  if (!seen) {
    const who = display(fk), txt = e.k === 'inv' ? '🎮 Einladung zu BLACKOUT – Raum ' + e.code : preview(e);
    notify(isG(ck) ? convName(ck) : who, isG(ck) ? who + ': ' + txt : txt, ck);
    blip(e.k === 'inv' ? [523, 659, 784] : [740, 988], .07);
  }
  if (typingT[ck]) { clearTimeout(typingT[ck][fk]); delete typingT[ck][fk]; }
  if (ck === sel) { renderMsgs(); renderTyping(); }
  renderFriends();
}
window.addEventListener('focus', () => { if (sel && unread[sel]) { unread[sel] = 0; lsSet('sparkchat.unread.' + me.key, unread); renderFriends(); } });
async function sharedFor(k, pub) {
  if (!pub) throw new Error('Kein Schlüssel');
  const c = shared.get(k); if (c && c.pub === pub) return c;
  const theirs = await C.importKey('raw', unb64(pub), ECDH, false, []);
  const bits = new Uint8Array(await C.deriveBits({ name: 'ECDH', public: theirs }, me.priv, 256));
  const pair = [me.key, k].sort().join('|');
  const e = { pub, bits, pair, msgKey: await hkdfKey(bits, 'spark-chat/dm/v1', pair) };
  shared.set(k, e); return e;
}

// ---------- Verlauf: nur auf diesem Gerät, verschlüsselt
function pushHist(ck, e) { e.ck = ck; const h = hist.get(ck) || []; h.push(e); if (h.length > 500) h.splice(0, h.length - 500); hist.set(ck, h); saveHist(ck); }
function findMsg(id) { for (const h of hist.values()) { const e = h.find(x => x.id === id); if (e) return e; } return null; }
const saveT = {};
function saveHist(ck) {
  if (!ck) return;
  clearTimeout(saveT[ck]);
  saveT[ck] = setTimeout(async () => {
    if (!me || !histKey) return;
    const data = (hist.get(ck) || []).map(({ ck: _, ...r }) => r);
    try { localStorage.setItem('sparkchat.h.' + me.key + '.' + ck, b64(await encWith(histKey, te.encode(JSON.stringify(data))))); } catch (e) { console.warn('Verlauf nicht gespeichert', e); }
  }, 400);
}
async function loadHist() {
  const pre = 'sparkchat.h.' + me.key + '.';
  for (const k of Object.keys(localStorage)) {
    if (!k.startsWith(pre)) continue;
    const ck = k.slice(pre.length);
    try {
      const list = JSON.parse(td.decode(await decWith(histKey, unb64(localStorage.getItem(k)))));
      // ältere Versionen ohne „from“: Absender aus „me“ ableiten
      hist.set(ck, list.map(e => Object.assign(e, { ck, from: e.from || (e.me ? me.key : ck) })));
    } catch (e) {}
  }
}
function clearHist(ck) {
  mediaDel(me.key + '|' + (ck ? ck + '|' : ''));
  const pre = 'sparkchat.h.' + me.key + '.';
  for (const k of Object.keys(localStorage)) if (k.startsWith(pre) && (!ck || k === pre + ck)) localStorage.removeItem(k);
  if (ck) hist.delete(ck); else hist.clear();
  renderAll();
}

// ---------- Bilder & Sprachnachrichten: verschlüsselt in der Gerätedatenbank (IndexedDB)
let idbP = null;
function idb() { return idbP || (idbP = new Promise((res, rej) => { const r = indexedDB.open('sparkchat', 1); r.onupgradeneeded = () => r.result.createObjectStore('img'); r.onsuccess = () => res(r.result); r.onerror = () => { idbP = null; rej(r.error); }; })); }
async function idbDo(mode, fn) { const db = await idb(); return new Promise((res, rej) => { const tx = db.transaction('img', mode), r = fn(tx.objectStore('img')); tx.oncomplete = () => res(r && r.result); tx.onerror = () => rej(tx.error); }); }
const mediaKey = (ck, id) => me.key + '|' + ck + '|' + id;
async function mediaPut(ck, id, bytes) { const enc = await encWith(histKey, bytes); await idbDo('readwrite', st => st.put(enc, mediaKey(ck, id))); }
async function mediaGet(ck, id) { try { const enc = await idbDo('readonly', st => st.get(mediaKey(ck, id))); return enc ? await decWith(histKey, new Uint8Array(enc)) : null; } catch (e) { return null; } }
const urlCache = new Map();
async function mediaUrl(ck, id, type) {
  const k = mediaKey(ck, id); if (urlCache.has(k)) return urlCache.get(k);
  const b = await mediaGet(ck, id); if (!b) return '';
  const u = URL.createObjectURL(new Blob([b], { type })); urlCache.set(k, u); return u;
}
async function mediaDel(prefix) { try { await idbDo('readwrite', st => st.delete(IDBKeyRange.bound(prefix, prefix + '￿'))); } catch (e) {} for (const k of urlCache.keys()) if (k.startsWith(prefix)) { URL.revokeObjectURL(urlCache.get(k)); urlCache.delete(k); } }
async function mediaRekey(oldKey, newKey) {
  const pre = me.key + '|', db = await idb();
  const all = await new Promise((res, rej) => { const out = [], tx = db.transaction('img', 'readonly'), r = tx.objectStore('img').openCursor(IDBKeyRange.bound(pre, pre + '￿')); r.onsuccess = () => { const c = r.result; if (c) { out.push([c.key, c.value]); c.continue(); } else res(out); }; r.onerror = () => rej(r.error); });
  for (const [k, v] of all) { try { const plain = await decWith(oldKey, new Uint8Array(v)); const enc = await encWith(newKey, plain); await idbDo('readwrite', st => st.put(enc, k)); } catch (e) {} }
}
// Bild verkleinern und als JPEG kodieren (Größe begrenzt, EXIF/Standort fällt dabei weg)
async function prepImage(file, max, maxBytes, square) {
  if (!file || !/^image\//.test(file.type)) throw new Error('Das ist kein Bild.');
  if (file.size > 40 * 1024 * 1024) throw new Error('Das Bild ist zu groß (max. 40 MB).');
  let src;
  try { src = await createImageBitmap(file, { imageOrientation: 'from-image' }); }
  catch (e) { src = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('Bild konnte nicht gelesen werden.')); i.src = URL.createObjectURL(file); }); }
  const W = src.width, H = src.height;
  let size = max, q = 0.82;
  for (let i = 0; i < 6; i++) {
    let sx = 0, sy = 0, sw = W, sh = H;
    if (square) { const m = Math.min(W, H); sx = (W - m) / 2; sy = (H - m) / 2; sw = sh = m; }
    const s = Math.min(1, size / Math.max(sw, sh)), w = Math.max(1, Math.round(sw * s)), h = Math.max(1, Math.round(sh * s));
    const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
    const cx = cv.getContext('2d'); cx.fillStyle = '#fff'; cx.fillRect(0, 0, w, h); cx.drawImage(src, sx, sy, sw, sh, 0, 0, w, h);
    const blob = await new Promise(r => cv.toBlob(r, 'image/jpeg', q));
    if (blob && blob.size <= maxBytes) return { bytes: new Uint8Array(await blob.arrayBuffer()), w, h };
    size = Math.round(size * 0.8); q = Math.max(0.5, q - 0.07);
  }
  throw new Error('Das Bild lässt sich nicht klein genug machen.');
}
async function sendImage(ck, file) {
  if (!convExists(ck)) return;
  try {
    toast('Bild wird vorbereitet …', true);
    const { bytes, w, h } = await prepImage(file, 1600, MAX_MEDIA);
    const id = rid();
    await mediaPut(ck, id, bytes);
    const body = { k: 'img', w, h }; if (replyTo) body.re = replyTo; cancelReply();
    sendMsg(ck, body, id);
    $('toast').className = 'toast';
  } catch (e) { toast(e.message); }
}
function showImage(url) {
  openModal('<span class="label">// Bild</span><img src="' + url + '" alt="Bild" style="display:block;max-width:100%;max-height:70vh;margin:10px auto 14px"><div class="btnrow"><a class="sec" style="display:inline-flex;align-items:center;text-decoration:none" href="' + url + '" download="spark-chat-bild.jpg">⬇ Speichern</a></div>', true);
}
function pickFile(fn) {
  const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
  inp.onchange = () => { if (inp.files && inp.files[0]) fn(inp.files[0]); };
  inp.click();
}
$('attach').onclick = () => { const ck = sel; if (ck) pickFile(f => sendImage(ck, f)); };
$('text').addEventListener('paste', e => { const it = [...(e.clipboardData ? e.clipboardData.items : [])].find(i => i.type.startsWith('image/')); if (it && sel) { e.preventDefault(); sendImage(sel, it.getAsFile()); } });
$('chat').addEventListener('dragover', e => { if (sel) e.preventDefault(); });
$('chat').addEventListener('drop', e => { const f = e.dataTransfer && [...e.dataTransfer.files].find(x => x.type.startsWith('image/')); if (f && sel) { e.preventDefault(); sendImage(sel, f); } });

// Sprachnachrichten: aufnehmen (max. 2 Minuten), abspielen
let rec = null, voiceNow = null;
$('recBtn').onclick = startRec;
async function startRec() {
  if (!sel || rec) return;
  if (!window.MediaRecorder) return toast('Sprachnachrichten gehen in diesem Browser leider nicht.');
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } }); }
  catch (e) { return toast('Kein Mikrofon gefunden oder nicht erlaubt.'); }
  const mime = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/ogg;codecs=opus', 'audio/webm'].find(t => MediaRecorder.isTypeSupported(t)) || '';
  const mr = new MediaRecorder(stream, Object.assign({ audioBitsPerSecond: 24000 }, mime ? { mimeType: mime } : {}));
  rec = { mr, stream, chunks: [], t0: Date.now(), ck: sel };
  mr.ondataavailable = e => { if (e.data && e.data.size) rec.chunks.push(e.data); };
  mr.start(250);
  $('recBar').hidden = false; $('compose').hidden = true;
  rec.tick = setInterval(() => { const s = (Date.now() - rec.t0) / 1000; $('recTime').textContent = fmtDur(s); if (s >= 120) stopRec(true); }, 250);
}
function stopRec(sendIt) {
  if (!rec) return;
  const r = rec; rec = null;
  clearInterval(r.tick);
  $('recBar').hidden = true; $('compose').hidden = false;
  r.mr.onstop = async () => {
    r.stream.getTracks().forEach(t => t.stop());
    if (!sendIt) return;
    const dur = (Date.now() - r.t0) / 1000;
    if (dur < 0.7) return toast('Zu kurz – halte die Aufnahme etwas länger.');
    const type = (r.mr.mimeType || 'audio/webm').split(';')[0];
    const bytes = new Uint8Array(await new Blob(r.chunks, { type }).arrayBuffer());
    if (bytes.length > MAX_MEDIA) return toast('Die Sprachnachricht ist zu lang.');
    const id = rid();
    await mediaPut(r.ck, id, bytes);
    const body = { k: 'voice', mime: type, dur: Math.round(dur * 10) / 10 }; if (replyTo) body.re = replyTo; cancelReply();
    sendMsg(r.ck, body, id);
  };
  r.mr.stop();
}
$('recSend').onclick = () => stopRec(true);
$('recCancel').onclick = () => stopRec(false);
async function playVoice(ck, el) {
  const btn = el.querySelector('.play'), bar = el.querySelector('.vbar i');
  if (voiceNow && voiceNow.el === el) { if (voiceNow.a.paused) { voiceNow.a.play(); btn.textContent = '❚❚'; } else { voiceNow.a.pause(); btn.textContent = '▶'; } return; }
  if (voiceNow) { voiceNow.a.pause(); voiceNow.btn.textContent = '▶'; }
  const url = await mediaUrl(ck, el.dataset.voice, el.dataset.mime || 'audio/webm');
  if (!url) return toast('Sprachnachricht nicht mehr vorhanden.');
  const a = new Audio(url);
  if (prefs.sink && a.setSinkId) a.setSinkId(prefs.sink).catch(() => {});
  voiceNow = { a, el, btn };
  a.ontimeupdate = () => { if (a.duration && isFinite(a.duration)) bar.style.width = (100 * a.currentTime / a.duration) + '%'; };
  a.onended = () => { btn.textContent = '▶'; bar.style.width = '0'; voiceNow = null; };
  a.play().then(() => { btn.textContent = '❚❚'; }).catch(() => toast('Dieses Audioformat kann dein Gerät nicht abspielen.'));
}

// ---------- Menü & Fenster
function placeMenu(m, anchor) {
  const r = anchor.getBoundingClientRect();
  m.style.top = Math.max(8, Math.min(innerHeight - m.offsetHeight - 8, r.bottom + 6)) + 'px';
  m.style.left = Math.max(8, Math.min(innerWidth - m.offsetWidth - 8, r.right - m.offsetWidth)) + 'px';
}
function showMenu(anchor, items) {
  const m = $('menu'); m.className = 'menu';
  m.innerHTML = items.map((it, i) => it === '-' ? '<hr>' : '<button data-i="' + i + '" class="' + (it.danger ? 'danger' : '') + '">' + it.label + '</button>').join('');
  m.hidden = false; placeMenu(m, anchor);
  for (const b of m.querySelectorAll('button')) b.onclick = () => { m.hidden = true; items[+b.dataset.i].fn(); };
}
document.addEventListener('mousedown', e => { if (!$('menu').hidden && !$('menu').contains(e.target) && !e.target.closest('#cMore,.acts')) $('menu').hidden = true; });
document.addEventListener('keydown', e => { if (e.key === 'Escape') { $('menu').hidden = true; closeModal(); } });
function openModal(html, wide) {
  $('sheet').style.width = wide ? 'min(720px,100%)' : '';
  $('sheet').innerHTML = '<button class="ico x" data-close>✕</button>' + html;
  $('modal').classList.add('open');
  for (const b of $('sheet').querySelectorAll('[data-close]')) b.onclick = closeModal;
  bindLinks($('sheet'));
}
let modalTick = null;
function closeModal() { $('modal').classList.remove('open'); clearInterval(modalTick); modalTick = null; }
$('modal').addEventListener('mousedown', e => { if (e.target === $('modal')) closeModal(); });
function bindLinks(root) { for (const a of root.querySelectorAll('[data-link]')) a.onclick = e => { e.preventDefault(); window.open(LINKS[a.dataset.link], '_blank'); }; }
bindLinks(document);
function confirmBox(title, text, btn, fn) {
  openModal('<h2>' + title + '</h2><p>' + text + '</p><div class="btnrow"><button class="btn red" id="cfOk">' + btn + '</button><button class="sec" data-close>Abbrechen</button></div>');
  $('cfOk').onclick = () => { closeModal(); fn(); };
}

$('cMore').onclick = () => {
  if (!sel) return;
  if (isG(sel)) {
    const g = groups.get(gidOf(sel)); if (!g) return;
    return showMenu($('cMore'), [
      { label: '👥 Mitglieder & Einstellungen', fn: () => showGroup(g.id) },
      { label: '🗑 Verlauf auf diesem Gerät löschen', fn: () => { clearHist(sel); toast('Verlauf gelöscht.', true); } },
      '-',
      { label: '🚪 Gruppe verlassen', danger: true, fn: () => confirmBox('Gruppe verlassen?', 'Du bekommst danach keine Nachrichten aus „' + esc(g.name) + '“ mehr.', 'VERLASSEN', () => send({ t: 'gleave', g: g.id })) },
    ]);
  }
  const f = friends.get(sel); if (!f) return;
  showMenu($('cMore'), [
    { label: '✏ Spitzname festlegen', fn: () => editNick(f) },
    { label: '🔐 Sicherheitsnummer anzeigen', fn: () => showSafety(f) },
    { label: '🗑 Verlauf auf diesem Gerät löschen', fn: () => { clearHist(f.key); toast('Verlauf gelöscht.', true); } },
    '-',
    { label: '🚩 Melden', fn: () => showReport(f.u, f.key) },
    { label: '⛔ Blockieren', danger: true, fn: () => confirmBox('⛔ ' + esc(f.u) + ' blockieren?', esc(f.u) + ' wird als Freund entfernt und kann dir keine Anfragen, Nachrichten oder Anrufe mehr schicken. ' + esc(f.u) + ' erfährt davon nichts.', 'BLOCKIEREN', () => send({ t: 'block', u: f.u, on: true })) },
    { label: '✖ Als Freund entfernen', danger: true, fn: () => confirmBox('Freundschaft beenden?', esc(f.u) + ' wird aus deiner Freundesliste entfernt. Ihr könnt euch danach keine Nachrichten mehr schicken.', 'ENTFERNEN', () => send({ t: 'unfriend', u: f.u })) },
  ]);
};
function showFriend(k) {
  const f = friends.get(k); if (!f) return;
  const [st] = stOf(f);
  openModal('<span class="label">// Profil</span><div style="display:flex;gap:16px;align-items:center;margin:8px 0 16px">' + avHtml(f.u).replace('class="av"', 'class="av" style="width:72px;height:72px;font-size:30px;' + avStyle(f.u) + '"') + '<div><h2 style="margin:0">' + esc(display(k)) + '</h2><div class="hint">' + (nicks[k] ? '@' + esc(f.u) + ' · ' : '') + esc(st) + '</div></div></div>' +
    (f.status ? '<p>💬 ' + esc(f.status) + '</p>' : '') +
    '<div class="btnrow"><button class="sec" id="pfNick">✏ Spitzname</button><button class="sec" id="pfSafe">🔐 Sicherheitsnummer</button></div>');
  $('pfNick').onclick = () => editNick(f); $('pfSafe').onclick = () => showSafety(f);
}
// Spitznamen sind privat: nur auf deinem Gerät gespeichert
function editNick(f) {
  openModal('<span class="label">// Spitzname</span><h2>✏ ' + esc(f.u) + '</h2><p class="hint">Nur du siehst den Spitznamen – er wird nicht verschickt.</p><label class="field"><span>Spitzname</span><input class="inp" id="nkIn" maxlength="24" value="' + esc(nicks[f.key] || '') + '"></label><div class="btnrow"><button class="btn cy" id="nkOk">SPEICHERN</button><button class="sec" id="nkClr">Entfernen</button></div>');
  const save = v => { if (v) nicks[f.key] = v; else delete nicks[f.key]; lsSet('sparkchat.nick.' + me.key, nicks); closeModal(); renderAll(); };
  $('nkOk').onclick = () => save($('nkIn').value.trim()); $('nkClr').onclick = () => save('');
  setTimeout(() => $('nkIn').focus(), 50);
}
async function showSafety(f) {
  const a = [me.pub, f.pub].sort().join('|'), h = new Uint8Array(await C.digest('SHA-256', te.encode(a)));
  const groups2 = []; for (let i = 0; i < 6; i++) groups2.push(String(((h[i * 3] << 16) | (h[i * 3 + 1] << 8) | h[i * 3 + 2]) % 100000).padStart(5, '0'));
  openModal('<span class="label">// Verschlüsselung prüfen</span><h2>🔐 SICHERHEITS<span>NUMMER</span></h2><p>Vergleiche diese Nummer mit ' + esc(f.u) + ' – am besten persönlich oder im Anruf. Wenn sie bei euch beiden gleich ist, kann niemand (auch nicht der Server) mitlesen.</p><div class="safety">' + groups2.slice(0, 3).join(' ') + '<br>' + groups2.slice(3).join(' ') + '</div>');
}
const REASONS = ['Belästigung oder Mobbing', 'Hass, Hetze oder Diskriminierung', 'Drohung oder Gewalt', 'Sexuelle Inhalte / Belästigung', 'Spam oder Betrug', 'Illegale Inhalte', 'Gefährdung von Kindern/Jugendlichen', 'Sonstiges'];
function showReport(name, ck) {
  const isFriend = friends.has(name.toLowerCase());
  openModal('<span class="label">// Inhalte melden</span><h2>🚩 ' + esc(name) + ' <span>MELDEN</span></h2>' +
    '<label class="field"><span>Grund</span><select class="inp" id="rpWhy">' + REASONS.map(r => '<option>' + r + '</option>').join('') + '</select></label>' +
    '<label class="field"><span>Was ist passiert? (freiwillig)</span><textarea class="inp" id="rpText" rows="3" maxlength="2000"></textarea></label>' +
    '<label class="check"><input type="checkbox" id="rpMsgs" checked> <span>Die letzten 20 Nachrichten ' + (isG(ck) ? 'dieser Gruppe' : 'dieses Chats') + ' mitschicken. <small class="hint">Weil alles verschlüsselt ist, können wir Inhalte nur prüfen, wenn du sie mitschickst.</small></span></label>' +
    '<label class="check"><input type="checkbox" id="rpBlock" checked> <span>' + esc(name) + ' außerdem blockieren</span></label>' +
    '<p class="hint">Bei akuter Gefahr wende dich sofort an die Polizei (110). Hilfe für Jugendliche: Nummer gegen Kummer 116 111.</p>' +
    '<div class="btnrow"><button class="btn red" id="rpGo">MELDUNG SENDEN</button><button class="sec" data-close>Abbrechen</button></div>');
  $('rpGo').onclick = () => {
    const msgs = $('rpMsgs').checked ? (hist.get(ck) || []).filter(e => e.k === 'text' && !e.hidden && !e.del).slice(-20).map(e => ({ from: e.me ? me.u : nameOf(e.from), text: e.text, ts: e.ts })) : [];
    send({ t: 'report', u: name, reason: $('rpWhy').value + (isG(ck) ? ' (Gruppe: ' + convName(ck) + ')' : ''), text: $('rpText').value.trim(), msgs });
    if ($('rpBlock').checked) send({ t: 'block', u: name, on: true });
    closeModal();
    if (!isFriend && $('rpBlock').checked) toast('Blockiert – du siehst keine Nachrichten mehr von ' + name + '.', true);
  };
}

// ---------- Gruppen erstellen & verwalten
$('newGroup').onclick = () => {
  const list = [...friends.values()].sort((a, b) => display(a.key).localeCompare(display(b.key)));
  openModal('<span class="label">// Neue Gruppe</span><h2>👥 GRUPPE <span>ERSTELLEN</span></h2>' +
    '<label class="field"><span>Name der Gruppe</span><input class="inp" id="gName" maxlength="40" placeholder="z. B. BLACKOUT-Squad"></label>' +
    '<div class="label" style="margin:6px 0">Freunde hinzufügen</div>' +
    (list.length ? '<div style="max-height:260px;overflow:auto">' + list.map(f => '<label class="pick"><input type="checkbox" value="' + esc(f.u) + '">' + avHtml(f.u) + '<b>' + esc(display(f.key)) + '</b></label>').join('') + '</div>' : '<p class="hint">Du hast noch keine Freunde – du kannst sie später hinzufügen.</p>') +
    '<div class="btnrow" style="margin-top:14px"><button class="btn cy" id="gGo">ERSTELLEN</button></div>');
  $('gGo').onclick = () => {
    const name = $('gName').value.trim();
    if (!name) return toast('Bitte gib der Gruppe einen Namen.');
    send({ t: 'gcreate', name, members: [...$('sheet').querySelectorAll('.pick input:checked')].map(i => i.value) });
    closeModal();
  };
  setTimeout(() => $('gName').focus(), 50);
};
function showGroup(id) {
  const g = groups.get(id); if (!g) return;
  const owner = g.owner === me.key, notIn = [...friends.values()].filter(f => !g.members.some(x => x.key === f.key));
  openModal('<span class="label">// Gruppe</span><h2>👥 ' + esc(g.name) + '</h2>' +
    (owner ? '<div class="grp"><span class="label">// Name</span><div style="display:flex;gap:8px"><input class="inp" id="gRen" maxlength="40" value="' + esc(g.name) + '"><button class="sec" id="gRenOk" style="flex:none;height:44px">Umbenennen</button></div></div>' : '') +
    '<div class="grp"><span class="label">// ' + g.members.length + ' Mitglieder</span>' + g.members.map(x => '<div class="member">' + avHtml(x.u) + '<div class="grow"><b>' + esc(x.key === me.key ? 'Du' : display(x.key)) + '</b>' + (x.key === g.owner ? ' <span class="hint">· Leiter</span>' : '') + (x.key !== me.key && !friends.has(x.key) ? ' <span class="hint">· kein Freund</span>' : '') + '</div>' +
      (x.key !== me.key ? '<button class="sec" data-rep="' + esc(x.u) + '">🚩</button>' + (owner ? '<button class="sec danger" data-kick="' + esc(x.u) + '">Entfernen</button>' : '') : '') + '</div>').join('') + '</div>' +
    (owner ? '<div class="grp"><span class="label">// Freunde hinzufügen</span>' + (notIn.length ? '<div style="display:flex;gap:8px"><select class="inp" id="gAddSel">' + notIn.map(f => '<option value="' + esc(f.u) + '">' + esc(display(f.key)) + '</option>').join('') + '</select><button class="sec" id="gAddOk" style="flex:none;height:44px">Hinzufügen</button></div>' : '<small class="hint">Alle deine Freunde sind schon drin.</small>') + '</div>' : '<p class="hint">Nur der Gruppenleiter kann Mitglieder hinzufügen oder entfernen.</p>') +
    '<div class="btnrow"><button class="sec danger" id="gLeave">🚪 Gruppe verlassen</button></div>', true);
  if (owner) {
    $('gRenOk').onclick = () => { const n = $('gRen').value.trim(); if (n) send({ t: 'grename', g: id, name: n }); closeModal(); };
    if ($('gAddOk')) $('gAddOk').onclick = () => { send({ t: 'gadd', g: id, u: $('gAddSel').value }); closeModal(); };
    for (const b of $('sheet').querySelectorAll('[data-kick]')) b.onclick = () => { send({ t: 'gkick', g: id, u: b.dataset.kick }); closeModal(); };
  }
  for (const b of $('sheet').querySelectorAll('[data-rep]')) b.onclick = () => showReport(b.dataset.rep, 'g:' + id);
  $('gLeave').onclick = () => confirmBox('Gruppe verlassen?', 'Du bekommst danach keine Nachrichten aus „' + esc(g.name) + '“ mehr.', 'VERLASSEN', () => send({ t: 'gleave', g: id }));
}

// ---------- Einstellungen
$('gear').onclick = $('gear2').onclick = () => showSettings();
function sw(id, on) { return '<button class="sw' + (on ? ' on' : '') + '" id="' + id + '"></button>'; }
const seg = (id, opts, cur) => '<div class="seg" id="' + id + '">' + opts.map(([v, l]) => '<button data-v="' + v + '" class="' + (v === cur ? 'on' : '') + '">' + l + '</button>').join('') + '</div>';
function showSettings() {
  if (!me) return;
  const canSink = !!(window.HTMLMediaElement && HTMLMediaElement.prototype.setSinkId);
  openModal('<span class="label">// Einstellungen</span><h2>⚙ SPARK <span>CHAT</span></h2>' +
    '<div class="grp"><span class="label">// Profil</span><div class="row"><div class="grow"><b>' + esc(me.u) + '</b><small>Mitglied seit ' + esc(me.created ? new Date(me.created).toLocaleDateString('de-DE') : '–') + '</small></div>' + avHtml(me.u) + '</div>' +
    '<div class="row"><div class="grow"><b>Profilbild</b><small>Sehen nur deine Freunde und Gruppen-Mitglieder.</small></div><div class="btnrow" style="margin:0"><button class="sec" id="avSet" style="height:34px">📷 Ändern</button>' + (avImg(me.u) ? '<button class="sec danger" id="avDel" style="height:34px">Entfernen</button>' : '') + '</div></div>' +
    '<div class="row"><div class="grow"><b>Status</b><small>' + esc(me.status || 'Kein Status') + '</small></div><button class="sec" id="stEdit" style="height:34px">💬 Ändern</button></div>' +
    '<div class="row"><div class="grow"><b>Unsichtbar</b><small>Freunde sehen dich als offline. Anrufe kommen dann nicht an.</small></div>' + sw('sInv', me.invisible) + '</div></div>' +
    '<div class="grp"><span class="label">// Aussehen</span>' +
    '<div class="row"><b>Design</b>' + seg('lkTheme', [['dark', '🌙 Dunkel'], ['light', '☀ Hell'], ['oled', '⬛ Schwarz'], ['system', '🖥 Wie System']], prefs.theme) + '</div>' +
    '<div class="row"><b>Farbe</b><div class="seg" id="lkAcc">' + ACCENTS.map(([n, c]) => '<button class="swatch' + (c === prefs.accent ? ' on' : '') + '" data-v="' + c + '" title="' + n + '" style="background:' + c + ';color:' + c + '"></button>').join('') + '</div></div>' +
    '<div class="row"><b>Schriftgröße</b>' + seg('lkSize', [['s', 'Klein'], ['m', 'Normal'], ['l', 'Groß'], ['xl', 'Sehr groß']], prefs.size) + '</div>' +
    '<div class="row"><b>Blasen</b>' + seg('lkBub', [['cut', '◆ Kantig'], ['round', '● Rund']], prefs.bubble) + '</div>' +
    '<div class="row"><b>Hintergrund</b>' + seg('lkBg', [['grid', 'Raster'], ['dots', 'Punkte'], ['plain', 'Schlicht']], prefs.bg) + '</div></div>' +
    '<div class="grp"><span class="label">// Benachrichtigungen & Ton</span><div class="row"><div class="grow"><b>Benachrichtigungen</b><small>Bei neuen Nachrichten, wenn das Fenster im Hintergrund ist' + (SPARK ? ' – im SPARK-Launcher auch, wenn das Fenster geschlossen ist' : '') + '</small></div>' + sw('sNot', prefs.notify) + '</div>' +
    '<div class="row"><div class="grow"><b>Töne</b><small>Signalton bei Nachrichten und Anrufen</small></div>' + sw('sSnd', prefs.sound) + '</div>' +
    (canInstall() ? '<div class="row"><div class="grow"><b>📲 Als App installieren</b><small>Eigenes Symbol auf dem Home-Bildschirm, Vollbild wie eine richtige App – kostenlos.</small></div><button class="sec" id="sInstall" style="height:34px">Installieren</button></div>' : '') +
    (pushSupported() ? '<div class="row"><div class="grow"><b>📱 Push-Benachrichtigungen</b><small>Auch wenn die App zu ist: „Du hast eine neue Nachricht“ – ohne Absender oder Inhalt.' + (iosNeedsHome() ? ' <b>iPhone:</b> Zuerst über Teilen → „Zum Home-Bildschirm“ hinzufügen und von dort öffnen.' : '') + '</small></div>' + sw('sPush', pushOn) + '</div>' : '') +
    (canSink ? '<div class="row"><div class="grow"><b>Lautsprecher / Kopfhörer</b><small>Für Anrufe und Sprachnachrichten</small></div><select class="inp" id="sSink" style="width:220px;height:36px"><option value="">Standard</option></select></div>' : '') + '</div>' +
    '<div class="grp"><span class="label">// Gesperrte Nutzer</span>' + (blocked.length ? blocked.map(u => '<div class="row"><b>' + esc(u) + '</b><button class="sec" data-unblock="' + esc(u) + '" style="height:32px">Aufheben</button></div>').join('') : '<small class="hint">Du hast niemanden blockiert.</small>') + '</div>' +
    '<div class="grp"><span class="label">// Sicherheit</span>' +
    '<label class="field"><span>Altes Passwort</span><input class="inp" type="password" id="pwOld" autocomplete="current-password"></label>' +
    '<label class="field"><span>Neues Passwort (min. 8 Zeichen)</span><input class="inp" type="password" id="pwNew" autocomplete="new-password"></label>' +
    '<label class="field"><span>Neues Passwort wiederholen</span><input class="inp" type="password" id="pwNew2" autocomplete="new-password"></label>' +
    '<div class="msgline" id="pwMsg"></div><div class="btnrow"><button class="sec" id="pwGo">Passwort ändern</button><button class="sec" id="sOut">Abmelden</button></div></div>' +
    '<div class="grp"><span class="label">// Deine Daten</span><div class="btnrow"><button class="sec" id="sData">📄 Meine Daten anzeigen</button><button class="sec" id="sClear">🗑 Verläufe auf diesem Gerät löschen</button></div>' +
    '<div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--line2)"><b style="color:var(--bad)">Konto löschen</b><p class="hint" style="margin:4px 0 8px">Löscht dein Konto, deine Freundesliste und alle Daten auf dem Server sofort und endgültig.</p>' +
    '<div style="display:flex;gap:8px"><input class="inp" type="password" id="delPw" placeholder="Passwort zur Bestätigung" autocomplete="current-password"><button class="sec danger" id="sDel" style="flex:none;height:44px">Konto löschen</button></div><div class="msgline" id="delMsg"></div></div></div>' +
    '<div class="grp"><span class="label">// Rechtliches</span><div class="btnrow"><a href="#" class="sec" style="display:inline-flex;align-items:center;text-decoration:none" data-link="terms">Nutzungsbedingungen</a><a href="#" class="sec" style="display:inline-flex;align-items:center;text-decoration:none" data-link="privacy">Datenschutz</a><a href="#" class="sec" style="display:inline-flex;align-items:center;text-decoration:none" data-link="contact">Kontakt</a><a href="#" class="sec" style="display:inline-flex;align-items:center;text-decoration:none" data-link="site">🌐 Webseite & Apps</a></div>' +
    '<p class="hint" style="margin:10px 0 0">SPARK Chat ' + VERSION + ' · Ende-zu-Ende-verschlüsselt (ECDH P-256 + AES-256-GCM)</p></div>', true);
  const segBind = (id, key) => { for (const b of $(id).querySelectorAll('button')) b.onclick = () => { prefs[key] = b.dataset.v; savePrefs(); applyLook(); for (const o of $(id).querySelectorAll('button')) o.classList.toggle('on', o === b); renderAll(); }; };
  segBind('lkTheme', 'theme'); segBind('lkAcc', 'accent'); segBind('lkSize', 'size'); segBind('lkBub', 'bubble'); segBind('lkBg', 'bg');
  $('sInv').onclick = () => { send({ t: 'invisible', on: !me.invisible }); me.invisible = !me.invisible; $('sInv').classList.toggle('on', me.invisible); renderMe(); };
  $('sNot').onclick = () => { prefs.notify = !prefs.notify; savePrefs(); $('sNot').classList.toggle('on', prefs.notify); if (prefs.notify && window.Notification && Notification.permission === 'default') Notification.requestPermission(); };
  $('sSnd').onclick = () => { prefs.sound = !prefs.sound; savePrefs(); $('sSnd').classList.toggle('on', prefs.sound); };
  if ($('sPush')) $('sPush').onclick = () => pushOn ? pushOff() : askPush();
  if ($('sInstall')) $('sInstall').onclick = installApp;
  if (canSink) {
    navigator.mediaDevices.enumerateDevices().then(list => {
      const outs = list.filter(d => d.kind === 'audiooutput' && d.deviceId && d.deviceId !== 'default');
      $('sSink').innerHTML = '<option value="">Standard</option>' + outs.map((d, i) => '<option value="' + esc(d.deviceId) + '"' + (d.deviceId === prefs.sink ? ' selected' : '') + '>' + esc(d.label || 'Ausgabe ' + (i + 1)) + '</option>').join('');
    }).catch(() => {});
    $('sSink').onchange = () => { prefs.sink = $('sSink').value; savePrefs(); if (call && call.el && call.el.setSinkId) call.el.setSinkId(prefs.sink || '').catch(() => {}); };
  }
  for (const b of $('sheet').querySelectorAll('[data-unblock]')) b.onclick = () => { send({ t: 'block', u: b.dataset.unblock, on: false }); b.closest('.row').remove(); };
  $('sOut').onclick = () => logout('Du wurdest abgemeldet.', true);
  $('stEdit').onclick = editStatus;
  $('avSet').onclick = () => pickFile(async file => {
    try { const { bytes } = await prepImage(file, 192, 22000, true); send({ t: 'avatar', img: b64(bytes) }); toast('Profilbild gespeichert.', true); setTimeout(showSettings, 600); }
    catch (e) { toast(e.message); }
  });
  if ($('avDel')) $('avDel').onclick = () => { send({ t: 'avatar', img: '' }); setTimeout(showSettings, 600); };
  $('sData').onclick = () => send({ t: 'mydata' });
  $('sClear').onclick = () => confirmBox('Verläufe löschen?', 'Alle Chatverläufe auf diesem Gerät werden gelöscht. Auf den Geräten deiner Freunde bleiben sie erhalten.', 'LÖSCHEN', () => { clearHist(); toast('Alle Verläufe auf diesem Gerät gelöscht.', true); });
  $('pwGo').onclick = changePw;
  $('sDel').onclick = deleteAccount;
}
let pwPending = null;
async function changePw() {
  const o = $('pwOld').value, n = $('pwNew').value, msg = s => { $('pwMsg').textContent = s; };
  if (n.length < 8) return msg('Das neue Passwort braucht mindestens 8 Zeichen.');
  if (n !== $('pwNew2').value) return msg('Die neuen Passwörter stimmen nicht überein.');
  msg('Schlüssel werden berechnet …');
  const old = await deriveKeys(me.u, o, me.salt);
  if (old.auth !== me.auth) return msg('Altes Passwort falsch.');
  const salt = hex(rnd(16)), keys = await deriveKeys(me.u, n, salt);
  pwPending = keys;
  send({ t: 'pw', auth: old.auth, salt, auth2: keys.auth, encPriv: await wrapPriv(await exportablePriv(), keys.wrapRaw) });
}
// Der private Schlüssel wird nicht exportierbar geladen – für die Neuverpackung einmal exportierbar entpacken
async function exportablePriv() {
  const d = await decWith(await aesKey(me.wrapRaw), unb64(me.encPrivRaw || ''));
  return C.importKey('pkcs8', d, ECDH, true, ['deriveBits']);
}
async function onPwOk(m) {
  if (!pwPending) return;
  const keys = pwPending; pwPending = null;
  me.auth = keys.auth; me.wrapRaw = keys.wrapRaw; me.salt = m.salt; me.encPrivRaw = m.encPriv;
  const oldHist = histKey;
  histKey = await hkdfKey(keys.wrapRaw, 'spark-chat/history/v1');
  for (const ck of hist.keys()) saveHist(ck);
  mediaRekey(oldHist, histKey);   // Bilder/Sprachnachrichten mit dem neuen Schlüssel neu verschlüsseln
  saveLogin();
  closeModal(); toast('Passwort geändert.', true);
}
async function deleteAccount() {
  const pw = $('delPw').value;
  if (!pw) { $('delMsg').textContent = 'Bitte gib dein Passwort ein.'; return; }
  const k = await deriveKeys(me.u, pw, me.salt);
  if (k.auth !== me.auth) { $('delMsg').textContent = 'Passwort falsch.'; return; }
  confirmBox('Konto endgültig löschen?', 'Das kann nicht rückgängig gemacht werden. Dein Benutzername wird frei und deine Freunde verlieren dich aus ihrer Liste.', 'ENDGÜLTIG LÖSCHEN', () => send({ t: 'delete', auth: k.auth }));
}
function showMyData(d) {
  const json = JSON.stringify(d, null, 2);
  openModal('<span class="label">// Auskunft nach Art. 15 DSGVO</span><h2>📄 MEINE <span>DATEN</span></h2><p class="hint">Das hat der Server über dich gespeichert. „pub“ ist dein öffentlicher Schlüssel, „encPriv“ dein privater Schlüssel – verschlüsselt mit deinem Passwort, der Server kann ihn nicht lesen. Deine Chatverläufe liegen nur auf deinen Geräten.</p><pre class="data">' + esc(json) + '</pre><div class="btnrow"><button class="sec" id="dlData">⬇ Als Datei speichern</button></div>', true);
  $('dlData').onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' })); a.download = 'spark-chat-meine-daten.json'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000); };
}

// ---------- Als App installieren: Android/Chrome direkt, iPhone über „Zum Home-Bildschirm“
let installEvt = null;
const standalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const isIOS = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); installEvt = e; });
const canInstall = () => !SPARK && !CAP && !standalone() && (installEvt || isIOS() || /Android/.test(navigator.userAgent));
async function installApp() {
  if (installEvt) { installEvt.prompt(); const r = await installEvt.userChoice.catch(() => null); installEvt = null; if (r && r.outcome === 'accepted') toast('📲 SPARK Chat wird installiert!', true); return; }
  openModal('<span class="label">// Als App installieren</span><h2>📲 SPARK CHAT <span>AUFS HANDY</span></h2>' +
    (isIOS() ? '<p><b>Am einfachsten:</b> <a class="btn cy" style="display:inline-flex;align-items:center;text-decoration:none;height:40px;margin:6px 0" href="https://nachtwache.onrender.com/SPARK-Chat.mobileconfig">📲 INSTALLIEREN</a><br><span class="hint">„Zulassen“ tippen, dann Einstellungen → „Profil geladen“ → Installieren.</span></p><p><b>Oder von Hand (Safari):</b></p><ol style="line-height:1.8"><li>Unten auf <b>Teilen</b> tippen (Quadrat mit Pfeil nach oben)</li><li><b>„Zum Home-Bildschirm“</b> wählen</li><li><b>Hinzufügen</b> tippen</li><li>SPARK Chat ab jetzt über das neue Symbol öffnen – dann läuft er wie eine App im Vollbild und kann Push-Benachrichtigungen bekommen.</li></ol><p class="hint">Funktioniert nur in Safari (ab iOS 16.4 mit Push).</p>'
      : '<p><b>Android (Chrome):</b> Oben rechts auf <b>⋮</b> tippen → <b>„App installieren“</b> bzw. „Zum Startbildschirm hinzufügen“.</p>') +
    '<p class="hint">Kostenlos, kein App Store nötig. Updates kommen automatisch.</p>');
}

// ---------- Push-Benachrichtigungen (Handy/Browser): nur nach Zustimmung, jederzeit abschaltbar
let pushOn = !!lsGet('sparkchat.push', false), swReg = null;
const pushSupported = () => !SPARK && !CAP && 'serviceWorker' in navigator && 'PushManager' in window && (location.protocol === 'https:' || location.hostname === 'localhost');
const iosNeedsHome = () => /iPhone|iPad/.test(navigator.userAgent) && !navigator.standalone && !matchMedia('(display-mode: standalone)').matches;
if (pushSupported()) navigator.serviceWorker.register('sw.js').then(r => { swReg = r; }).catch(() => {});
if ('serviceWorker' in navigator) navigator.serviceWorker.addEventListener('message', e => { if (e.data && e.data.open && convExists(e.data.open)) openChat(e.data.open); });
const b64u = s => { const p = '='.repeat((4 - s.length % 4) % 4); return unb64((s + p).replace(/-/g, '+').replace(/_/g, '/')); };
function askPush() {
  if (iosNeedsHome()) return toast('Auf dem iPhone: zuerst über Teilen → „Zum Home-Bildschirm“ hinzufügen und SPARK Chat von dort öffnen.');
  openModal('<span class="label">// Einwilligung</span><h2>📱 PUSH-<span>BENACHRICHTIGUNGEN</span></h2>' +
    '<p>Damit du auch bei geschlossener App erfährst, dass jemand geschrieben hat, speichert der Server eine <b>Push-Adresse</b> deines Browsers. Die Benachrichtigung wird über den Push-Dienst deines Browsers zugestellt – z. B. <b>Google</b> (Chrome/Android), <b>Apple</b> (iPhone/Safari), <b>Mozilla</b> (Firefox) oder <b>Microsoft</b> (Edge), auch in die USA.</p>' +
    '<p>Sie enthält nur <b>„SPARK Chat – Du hast eine neue Nachricht“</b>: keinen Absender, keinen Inhalt, verschlüsselt. Der Push-Dienst erfährt nur, dass und wann eine Benachrichtigung an dein Gerät geht.</p>' +
    '<p class="hint">Freiwillig – du kannst die Einwilligung jederzeit in den Einstellungen widerrufen (Schalter aus). Beim Abmelden wird Push für dieses Gerät automatisch abgeschaltet. Mehr in der <a href="#" data-link="privacy">Datenschutzerklärung</a>.</p>' +
    '<label class="check"><input type="checkbox" id="pcOk"> <span>Ich bin einverstanden, dass SPARK Chat mir Push-Benachrichtigungen schickt.</span></label>' +
    '<div class="btnrow"><button class="btn cy" id="pcGo">EINSCHALTEN</button><button class="sec" data-close>Abbrechen</button></div>');
  $('pcGo').onclick = async () => { if (!$('pcOk').checked) return toast('Bitte setze zuerst das Häkchen.'); closeModal(); await pushEnable(); };
}
async function pushEnable() {
  try {
    if (!me || !me.vapid) return toast('Push ist gerade nicht verfügbar – bitte später nochmal.');
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') return toast('Benachrichtigungen sind im Browser blockiert. Erlaube sie in den Website-Einstellungen.');
    const reg = swReg || await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (sub && sub.options && sub.options.applicationServerKey && b64(sub.options.applicationServerKey) !== b64(b64u(me.vapid))) { await sub.unsubscribe(); sub = null; }
    if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64u(me.vapid) });
    send({ t: 'pushsub', sub: sub.toJSON(), consent: true });
  } catch (e) { toast('Push konnte nicht eingeschaltet werden: ' + e.message); }
}
async function pushOff(silent) {
  try {
    if (!pushSupported()) return;
    const reg = swReg || await navigator.serviceWorker.getRegistration();
    const sub = reg && await reg.pushManager.getSubscription();
    if (sub) { send({ t: 'pushdel', endpoint: sub.endpoint }); await sub.unsubscribe(); }
  } catch (e) {}
  pushOn = false; lsSet('sparkchat.push', false);
  if ($('sPush')) $('sPush').classList.remove('on');
  if (!silent) toast('Push-Benachrichtigungen sind aus.', true);
}
// Nach dem Anmelden: Push-Abo dieses Geräts mit dem Server abgleichen (z. B. nach Konto-Wechsel)
async function syncPush() {
  if (!pushOn || !pushSupported() || Notification.permission !== 'granted') return;
  try { const reg = swReg || await navigator.serviceWorker.ready; const sub = await reg.pushManager.getSubscription(); if (sub) send({ t: 'pushsub', sub: sub.toJSON(), consent: true }); else pushEnable(); } catch (e) {}
}

// ---------- BLACKOUT-Einladungen
async function currentRoom() { try { if (SPARK && SPARK.rooms) { const r = await SPARK.rooms(); return (r && r.blackout && r.blackout.room) || ''; } } catch (e) {} return ''; }
$('cInvite').onclick = async () => {
  if (!sel) return;
  const ck = sel, room = await currentRoom(), canLaunch = !!(SPARK && SPARK.launch);
  openModal('<span class="label">// Zu BLACKOUT einladen</span><h2>🎮 ' + esc(convName(ck)) + ' <span>EINLADEN</span></h2>' +
    '<div id="invRoom"></div>' +
    '<label class="field" style="margin-top:12px"><span>Raum-Code (steht in BLACKOUT oben, wenn du hostest)</span><input class="inp" id="invCode" maxlength="8" style="text-transform:uppercase;font:700 18px var(--f-mono);letter-spacing:4px" value="' + esc(room) + '"></label>' +
    '<div class="btnrow"><button class="btn" id="invGo">EINLADUNG SENDEN</button>' + (canLaunch ? '<button class="sec" id="invStart">▶ BLACKOUT starten</button>' : '') + '</div>');
  const upd = r => { $('invRoom').innerHTML = r ? '<div class="okbox">✔ Du bist gerade in BLACKOUT-Raum <b>' + esc(r) + '</b>.</div>' : '<p class="hint">Starte BLACKOUT und wähle <b>Online → Hosten</b>. ' + (canLaunch ? 'Der Raum-Code wird dann automatisch erkannt.' : 'Gib danach den Raum-Code hier ein.') + '</p>'; };
  upd(room);
  if (canLaunch) {
    $('invStart').onclick = async () => { const r = await SPARK.launch('blackout', {}); if (!r || !r.ok) toast((r && r.error) || 'BLACKOUT konnte nicht gestartet werden.'); };
    modalTick = setInterval(async () => { const r = await currentRoom(); if (r && r !== $('invCode').value) { $('invCode').value = r; upd(r); } }, 1500);
  }
  $('invGo').onclick = () => {
    const code = $('invCode').value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (!/^[A-Z0-9]{3,8}$/.test(code)) return toast('Bitte einen gültigen Raum-Code eingeben.');
    sendMsg(ck, { k: 'inv', game: 'blackout', code });
    closeModal();
  };
};
async function joinGame(code) {
  if (SPARK && SPARK.launch) {
    const r = await SPARK.launch('blackout', { join: code });
    if (r && r.ok) { toast(r.running ? 'BLACKOUT läuft schon – gib dort unter Online → Beitreten den Code ' + code + ' ein.' : 'BLACKOUT startet …', true); return; }
    toast((r && r.error) || 'BLACKOUT konnte nicht gestartet werden.');
    if (r && /installiert/i.test(r.error || '')) return;
  }
  window.open(GAME_WEB + '?join=' + encodeURIComponent(code), '_blank');
}
// Aktivität für Freunde: „spielt BLACKOUT“
async function updateActivity() {
  let a = '';
  try { if (SPARK && SPARK.running) { const r = await SPARK.running(); if (r && r.includes('blackout')) a = 'spielt BLACKOUT'; } } catch (e) {}
  if (call && call.state === 'live') a = a || 'im Anruf';
  if (a !== actNow) { actNow = a; send({ t: 'act', act: a }); renderMe(); }
}
setInterval(updateActivity, 8000);

// ---------- Sprachanrufe: Mikrofon → 16 kHz → µ-law → AES-GCM → Server → Freund
// Wiedergabe über eine lokale WebRTC-Schleife, damit die Echo-Unterdrückung des Browsers greift.
const RATE = 16000, FRAME = 960;   // 60 ms pro Paket
const MU_DEC = new Float32Array(256);
for (let u = 0; u < 256; u++) { const v = ~u & 0xff, sign = v & 0x80, ex = (v >> 4) & 7, man = v & 0x0f; let s = ((man << 3) + 132) << ex; s -= 132; MU_DEC[u] = (sign ? -s : s) / 32768; }
function muEnc(x) {
  let s = Math.max(-1, Math.min(1, x)) * 32635; const sign = s < 0 ? 0x80 : 0; if (sign) s = -s; s = (s | 0) + 132;
  let ex = 7; for (let m = 0x4000; (s & m) === 0 && ex > 0; m >>= 1) ex--;
  return ~(sign | (ex << 4) | ((s >> (ex + 3)) & 0x0f)) & 0xff;
}
const WORKLET = 'class Cap extends AudioWorkletProcessor{process(i,o){const c=i[0]&&i[0][0];if(c)this.port.postMessage(c.slice(0));return true}}registerProcessor("cap",Cap);';
let callMini = false;
$('callMin').onclick = e => { e.stopPropagation(); callMini = true; callUi(); };
$('call').addEventListener('click', () => { if (callMini) { callMini = false; callUi(); } });
function callUi() {
  if (!call) { $('call').hidden = true; callMini = false; if (sel) renderHead(); return; }
  $('call').classList.toggle('mini', callMini && call.state !== 'end' && !(call.state === 'ring' && call.dir === 'in'));
  $('callMin').hidden = call.state === 'end' || (call.state === 'ring' && call.dir === 'in');
  const iosWeb = !CAP && /iPhone|iPad|iPod/.test(navigator.userAgent) && call.state === 'live';
  $('callHint').hidden = !iosWeb;
  if (iosWeb) $('callHint').textContent = '📱 iPhone: Bleib während des Anrufs in SPARK Chat – im Hintergrund pausiert Apple Ton und Mikrofon. Zum Schreiben den Anruf einklappen (▁).';
  const f = friends.get(call.fk), name = f ? display(f.key) : call.fk;
  $('call').hidden = false;
  $('call').classList.toggle('ring', call.state === 'ring');
  $('callName').textContent = name;
  setAv($('callAv'), f ? f.u : name);
  $('callLbl').textContent = call.state === 'ring' ? (call.dir === 'in' ? '// Eingehender Anruf' : '// Ruft an …') : call.state === 'end' ? '// Anruf beendet' : '// Sprachanruf · 🔒 verschlüsselt';
  let b = '';
  if (call.state === 'ring' && call.dir === 'in') b = '<button class="btn ok" id="caYes">📞 ANNEHMEN</button><button class="btn red" id="caNo">ABLEHNEN</button>';
  else if (call.state !== 'end') b = (call.state === 'live' ? '<button class="sec' + (call.muted ? ' on' : '') + '" id="caMute" title="Mikrofon">' + (call.muted ? '🔇 Stumm' : '🎙 Mikro') + '</button><button class="sec' + (call.loud ? ' on' : '') + '" id="caLoud" title="Lauter (Lautsprecher)">' + (call.loud ? '🔊 Laut' : '🔈 Normal') + '</button>' : '') + '<button class="btn red" id="caEnd">AUFLEGEN</button>';
  $('callBtns').innerHTML = b;
  if ($('caYes')) $('caYes').onclick = acceptCall;
  if ($('caNo')) $('caNo').onclick = () => { send({ t: 'call', op: 'decline', cid: call.cid }); endCall(false, 'Abgelehnt', true); };
  if ($('caEnd')) $('caEnd').onclick = () => endCall(true);
  if ($('caMute')) $('caMute').onclick = () => { call.muted = !call.muted; callUi(); };
  if ($('caLoud')) $('caLoud').onclick = () => { call.loud = !call.loud; setVolume(call); callUi(); };
  callStatus();
  if (sel) renderHead();
}
function callStatus() {
  if (!call) return;
  const s = call.state === 'live' ? (() => { const t = Math.floor((Date.now() - call.t0) / 1000); return fmtDur(t) + (call.noMic ? ' · ohne Mikrofon' : ''); })()
    : call.state === 'ring' ? (call.dir === 'in' ? 'möchte mit dir sprechen' : 'klingelt …') : call.why || '';
  if (call.state === 'live' && call.hold) return void ($('callSt').textContent = '⚠ Verbindung weg – verbinde neu …');
  if (call.state === 'live' && call.peerHold) return void ($('callSt').textContent = '⚠ ' + display(call.fk) + ' hat kurz keine Verbindung …');
  $('callSt').textContent = s;
}
setInterval(callStatus, 1000);
$('cCall').onclick = () => {
  const f = friends.get(sel); if (!f || (call && call.state !== 'end')) return;
  if (!f.on) return toast(f.u + ' ist gerade offline.');
  if (call) { cleanupAudio(call); call = null; }
  call = { cid: rid(), fk: f.key, dir: 'out', state: 'ring', ctx: audioCtx() };
  send({ t: 'call', op: 'ring', u: f.u, cid: call.cid });
  ringtone(true); callUi();
};
function onCall(m) {
  const fk = String(m.u || '').toLowerCase();
  if (m.op === 'ring') {
    // Beide rufen sich gleichzeitig an → eigenen Anruf zurückziehen und den des Freundes annehmen
    if (call && call.dir === 'out' && call.state === 'ring' && call.fk === fk) { send({ t: 'call', op: 'end', cid: call.cid }); call.cid = m.cid; call.dir = 'in'; acceptCall(); return; }
    if ((call && call.state !== 'end') || !friends.has(fk)) { send({ t: 'call', op: 'decline', cid: m.cid }); return; }
    if (call) { cleanupAudio(call); call = null; }
    call = { cid: m.cid, fk, dir: 'in', state: 'ring' };
    ringtone(true); callUi();
    notify('📞 ' + display(fk) + ' ruft an', 'Klick hier, um den Anruf anzunehmen.', fk);
    if (SPARK && SPARK.show) SPARK.show();
    return;
  }
  if (m.op === 'joined' && call && call.cid === m.old) { call.cid = m.cid; startAudio(); return; }   // beide haben gleichzeitig angerufen
  if (!call || call.cid !== m.cid) return;
  if (m.op === 'hold') { call.peerHold = true; callUi(); return; }
  if (m.op === 'resumed') { call.peerHold = false; call.next = 0; callUi(); return; }
  if (m.op === 'accept' && call.dir === 'out' && call.state === 'ring') { startAudio(); return; }
  if (m.op === 'end') endCall(false, m.why || 'Aufgelegt');
}
async function acceptCall() {
  if (!call || call.state !== 'ring') return;
  ringtone(false);
  if (!call.ctx || call.ctx.state === 'closed') call.ctx = audioCtx();
  send({ t: 'call', op: 'accept', cid: call.cid });
  startAudio();
}
async function startAudio() {
  const c = call; if (!c || c.state === 'live') return;
  ringtone(false);
  c.state = 'live'; c.t0 = Date.now(); c.acc = 0; c.accN = 0; c.pos = 0; c.out = new Float32Array(FRAME); c.outN = 0; c.next = 0; c.quiet = 0;
  callUi(); updateActivity();
  try {
    c.key = await callKey(c.fk, c.cid);
    c.ctx = c.ctx || audioCtx();
    if (c.ctx.state === 'suspended') c.ctx.resume().catch(() => {});
    // Wiedergabe: Ton → Lautstärke → Begrenzer → (WebRTC-Schleife für Echo-Unterdrückung | Lautsprecher)
    c.gain = c.ctx.createGain(); c.comp = c.ctx.createDynamicsCompressor();
    c.comp.threshold.value = -10; c.comp.ratio.value = 8;
    c.gain.connect(c.comp); setVolume(c);
    await routeOutput(c);
    try {
      c.stream = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 } });
    } catch (e) { c.noMic = true; toast('Kein Mikrofon gefunden oder nicht erlaubt – du kannst nur zuhören.'); }
    if (call !== c) return cleanupAudio(c);
    if (c.stream) {
      const url = URL.createObjectURL(new Blob([WORKLET], { type: 'application/javascript' }));
      await c.ctx.audioWorklet.addModule(url);
      const src = c.ctx.createMediaStreamSource(c.stream), node = new AudioWorkletNode(c.ctx, 'cap'), mute = c.ctx.createGain();
      mute.gain.value = 0; node.connect(mute); mute.connect(c.ctx.destination);
      node.port.onmessage = e => capture(c, e.data);
      src.connect(node); c.node = node;
      const tr = c.stream.getAudioTracks()[0]; if (tr) tr.onended = () => { if (!document.hidden && call === c) restartMic(c); };
    }
    wakeOn(c); mediaSession(c);
    keepAwakeAudio(c);
    if (CALLSVC) CALLSVC.start({ who: display(c.fk) }).catch(() => {});
  } catch (e) { console.error(e); toast('Audio konnte nicht gestartet werden: ' + e.message); }
}
// Verbindung kurz weg (Handy im Hintergrund, Funkloch): Gespräch 40 s lang halten und beim Neuverbinden fortsetzen
function holdCall() {
  const c = call; if (!c || c.hold) return;
  c.hold = true; callUi();
  c.holdT = setTimeout(() => { if (call === c && c.hold) endCall(false, 'Verbindung verloren'); }, 40000);
}
// Bildschirm während des Anrufs anlassen (sonst schickt das Handy die App in den Ruhezustand)
async function wakeOn(c) { try { if (navigator.wakeLock && !document.hidden) { c.wake = await navigator.wakeLock.request('screen'); } } catch (e) {} }
function mediaSession(c) {
  try {
    if (!('mediaSession' in navigator)) return;
    navigator.mediaSession.metadata = new MediaMetadata({ title: 'Anruf mit ' + display(c.fk), artist: 'SPARK Chat', artwork: [{ src: 'icon-512.png', sizes: '512x512', type: 'image/png' }] });
    try { navigator.mediaSession.setActionHandler('hangup', () => endCall(true)); } catch (e) {}
    try { navigator.mediaSession.setActionHandler('togglemicrophone', () => { c.muted = !c.muted; callUi(); }); } catch (e) {}
  } catch (e) {}
}
// Zurück in die App: Ton fortsetzen, Mikrofon neu holen falls das Handy es abgeschaltet hat
document.addEventListener('visibilitychange', async () => {
  const c = call; if (!c || c.state !== 'live' || document.hidden) return;
  try { if (c.ctx && c.ctx.state !== 'running') await c.ctx.resume(); } catch (e) {}
  try { if (c.el) c.el.play().catch(() => {}); } catch (e) {}
  if (!c.wake || c.wake.released) wakeOn(c);
  const tr = c.stream && c.stream.getAudioTracks()[0];
  if (c.stream && (!tr || tr.readyState === 'ended')) restartMic(c);
});
async function restartMic(c) {
  try {
    const st = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true, channelCount: 1 } });
    if (call !== c) { st.getTracks().forEach(t => t.stop()); return; }
    try { c.stream.getTracks().forEach(t => t.stop()); } catch (e) {}
    c.stream = st; c.ctx.createMediaStreamSource(st).connect(c.node);
  } catch (e) {}
}
function setVolume(c) { if (c && c.gain) c.gain.gain.value = c.loud ? 2.6 : 1; }
async function routeOutput(c) {
  try {
    if (!window.RTCPeerConnection) throw new Error('kein WebRTC');
    const dst = c.ctx.createMediaStreamDestination(); c.comp.connect(dst);
    const p1 = new RTCPeerConnection(), p2 = new RTCPeerConnection(); c.pcs = [p1, p2];
    p1.onicecandidate = e => e.candidate && p2.addIceCandidate(e.candidate).catch(() => {});
    p2.onicecandidate = e => e.candidate && p1.addIceCandidate(e.candidate).catch(() => {});
    const el = c.el = new Audio(); el.autoplay = true;
    p2.ontrack = e => { el.srcObject = e.streams[0] || new MediaStream([e.track]); if (prefs.sink && el.setSinkId) el.setSinkId(prefs.sink).catch(() => {}); el.play().catch(() => {}); };
    p1.addTrack(dst.stream.getAudioTracks()[0], dst.stream);
    const off = await p1.createOffer(); await p1.setLocalDescription(off); await p2.setRemoteDescription(off);
    const ans = await p2.createAnswer(); await p2.setLocalDescription(ans); await p1.setRemoteDescription(ans);
    for (let i = 0; i < 25 && p1.connectionState !== 'connected'; i++) await sleep(100);
    if (p1.connectionState !== 'connected') throw new Error('Schleife nicht verbunden');
  } catch (e) {
    // Rückfall: direkt abspielen
    if (c.pcs) c.pcs.forEach(p => { try { p.close(); } catch (e2) {} }); c.pcs = null;
    if (c.el) { c.el.srcObject = null; c.el = null; }
    try { c.comp.disconnect(); } catch (e2) {}
    c.comp.connect(c.ctx.destination);
  }
}
function capture(c, f) {
  if (call !== c || c.state !== 'live' || c.muted) return;
  const r = c.ctx.sampleRate / RATE;
  for (let i = 0; i < f.length; i++) {
    c.acc += f[i]; c.accN++; c.pos += 1;
    if (c.pos >= r) {
      c.pos -= r; c.out[c.outN++] = c.acc / c.accN; c.acc = 0; c.accN = 0;
      if (c.outN === FRAME) { sendFrame(c, c.out); c.outN = 0; }
    }
  }
}
async function sendFrame(c, samples) {
  if (!wsReady() || ws.bufferedAmount > 48 * 1024 || !c.key) return;   // Leitung voll → Paket auslassen statt Verzögerung
  const bytes = new Uint8Array(FRAME); let e = 0;
  for (let i = 0; i < FRAME; i++) { bytes[i] = muEnc(samples[i]); e += samples[i] * samples[i]; }
  const rms = Math.sqrt(e / FRAME);
  // Stille nicht übertragen (spart Daten und verhindert Rauschen/Echo); kurz nachlaufen lassen
  if (rms < 0.006) { if (++c.quiet > 8) return; } else c.quiet = 0;
  talk('callAv', rms > 0.02 ? 'me' : '');
  const d = await encWith(c.key, bytes);
  send({ t: 'a', cid: c.cid, d: b64(d) });
}
async function onAudio(m) {
  const c = call; if (!c || c.cid !== m.cid || !c.key || !c.ctx || !c.gain) return;
  let bytes; try { bytes = await decWith(c.key, unb64(m.d)); } catch (e) { return; }
  const buf = c.ctx.createBuffer(1, bytes.length, RATE), ch = buf.getChannelData(0); let e = 0;
  for (let i = 0; i < bytes.length; i++) { ch[i] = MU_DEC[bytes[i]]; e += ch[i] * ch[i]; }
  talk('callAv', Math.sqrt(e / bytes.length) > 0.02 ? 'them' : '');
  const t = c.ctx.currentTime;
  if (c.next < t + 0.02) c.next = t + 0.1;      // Puffer leer → kurz vorpuffern
  const ahead = c.next - t;
  if (ahead > 0.6) return;                       // viel zu spät → verwerfen
  const rate = ahead > 0.25 ? 1.07 : 1;          // zu viel Verzögerung → etwas schneller abspielen statt abhacken
  const s = c.ctx.createBufferSource(); s.buffer = buf; s.playbackRate.value = rate; s.connect(c.gain); s.start(c.next); c.next += buf.duration / rate;
}
let talkT = 0;
function talk(id, who) { if (who) { talkT = Date.now(); $(id).classList.add('talk'); } else if (Date.now() - talkT > 250) $(id).classList.remove('talk'); }
function audioCtx() { const ctx = new (window.AudioContext || window.webkitAudioContext)({ latencyHint: 'interactive' }); ctx.resume && ctx.resume().catch(() => {}); return ctx; }
async function callKey(fk, cid) { const f = friends.get(fk); const s = await sharedFor(fk, f && f.pub); return hkdfKey(s.bits, 'spark-chat/call/v1/' + cid, s.pair); }
// Browser frieren stille Seiten im Hintergrund ein (Chrome/Android). Ein unhörbar leises Rauschen hält den Anruf aktiv.
function keepAwakeAudio(c) {
  try {
    const len = c.ctx.sampleRate, buf = c.ctx.createBuffer(1, len, c.ctx.sampleRate), d = buf.getChannelData(0);
    for (let i = 0; i < len; i++) d[i] = (Math.random() * 2 - 1) * 0.0004;
    const src = c.ctx.createBufferSource(); src.buffer = buf; src.loop = true; src.connect(c.ctx.destination); src.start(); c.noise = src;
  } catch (e) {}
}
function cleanupAudio(c) {
  clearTimeout(c.holdT);
  try { if (c.noise) c.noise.stop(); } catch (e) {}
  if (CALLSVC && c.state === 'live') CALLSVC.stop().catch(() => {});
  try { if (c.wake) c.wake.release(); } catch (e) {}
  try { if ('mediaSession' in navigator) navigator.mediaSession.metadata = null; } catch (e) {}
  try { if (c.stream) c.stream.getTracks().forEach(t => t.stop()); } catch (e) {}
  try { if (c.node) c.node.port.onmessage = null; } catch (e) {}
  try { if (c.pcs) c.pcs.forEach(p => p.close()); } catch (e) {}
  try { if (c.el) { c.el.pause(); c.el.srcObject = null; } } catch (e) {}
  try { if (c.ctx && c.ctx.state !== 'closed') c.ctx.close(); } catch (e) {}
}
function endCall(local, why, silent) {
  const c = call; if (!c || c.state === 'end') return;
  if (local) send({ t: 'call', op: 'end', cid: c.cid });
  ringtone(false); cleanupAudio(c);
  if (c.state === 'live') { const t = Math.floor((Date.now() - c.t0) / 1000); sysMsg(c.fk, '📞 Anruf · ' + fmtDur(t)); }
  else if (c.dir === 'in' && !silent) { sysMsg(c.fk, '📞 Verpasster Anruf von ' + display(c.fk)); if (c.fk !== sel) { unread[c.fk] = (unread[c.fk] || 0) + 1; renderFriends(); } }
  c.state = 'end'; c.why = why || 'Aufgelegt'; callUi();
  blip([440, 330], .12);
  setTimeout(() => { if (call === c) { call = null; callUi(); updateActivity(); } }, 1800);
}

// ---------- Töne & Benachrichtigungen
let actx = null, ringT = null;
function blip(freqs, dur, vol) {
  if (!prefs.sound) return;
  try {
    actx = actx || new (window.AudioContext || window.webkitAudioContext)();
    if (actx.state === 'suspended') actx.resume().catch(() => {});
    let t = actx.currentTime;
    for (const f of freqs) {
      const o = actx.createOscillator(), g = actx.createGain();
      o.type = 'triangle'; o.frequency.value = f; g.gain.setValueAtTime(vol || .08, t); g.gain.exponentialRampToValueAtTime(.0001, t + dur);
      o.connect(g); g.connect(actx.destination); o.start(t); o.stop(t + dur + .02); t += dur * .9;
    }
  } catch (e) {}
}
function ringtone(on) {
  clearInterval(ringT); ringT = null;
  if (on) { const r = () => blip(call && call.dir === 'in' ? [784, 988, 784, 988] : [440, 440], .18, .07); r(); ringT = setInterval(r, 2200); }
}
let lnId = 1;
function notify(title, body, ck) {
  if (!prefs.notify) return;
  if (LN) {   // App: Benachrichtigung über das Handy, solange die App im Hintergrund noch läuft
    if (!document.hidden) return;
    LN.schedule({ notifications: [{ id: lnId++, title, body: String(body).slice(0, 140), extra: { ck: ck || '' } }] }).catch(() => {});
    return;
  }
  if (!window.Notification) return;
  if (document.hasFocus() && !document.hidden) return;
  try {
    if (Notification.permission === 'default') { Notification.requestPermission(); return; }
    if (Notification.permission !== 'granted') return;
    const n = new Notification(title, { body: String(body).slice(0, 140), silent: true, icon: 'icon.png', tag: ck || undefined });
    n.onclick = () => { if (SPARK && SPARK.show) SPARK.show(); window.focus(); if (ck && convExists(ck)) openChat(ck); n.close(); };
  } catch (e) {}
}
let toastT = null;
function toast(msg, ok) { const t = $('toast'); t.textContent = msg; t.className = 'toast show' + (ok ? ' ok' : ''); clearTimeout(toastT); toastT = setTimeout(() => { t.className = 'toast' + (ok ? ' ok' : ''); }, 4200); }
function conn(s) { $('conn').hidden = !s; $('conn').textContent = s || ''; }

setMode(false);
if (!(SPARK && SPARK.vault)) { $('aStay').checked = !!CAP; $('stayHint').textContent = CAP ? '(auf diesem Handy)' : '(nur auf deinem eigenen Gerät)'; }
if (LN) LN.addListener('localNotificationActionPerformed', a => { const ck = a && a.notification && a.notification.extra && a.notification.extra.ck; if (ck && convExists(ck)) openChat(ck); });
autoLogin();
// Für Tests
window.__chat = { get me() { return me; }, friends: () => friends, groups: () => groups, hist: () => hist, get call() { return call; }, send, SERVER };
})();
