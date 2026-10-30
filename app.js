// ============================================================
// VaultGuard v3 — Tema, TOTP, HIBP, history
// ============================================================

// ---------- THEME ----------
function initTheme() {
  const saved = localStorage.getItem('vg-theme');
  const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
  const theme = saved || (prefersLight ? 'light' : 'dark');
  applyTheme(theme);
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem('vg-theme')) applyTheme(e.matches ? 'light' : 'dark');
  });
}
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.getElementById('theme-icon').textContent = theme === 'light' ? '☀️' : '🌙';
  document.getElementById('theme-toggle').setAttribute('aria-pressed', theme === 'light');
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
  localStorage.setItem('vg-theme', next);
  showToast(`Tema ${next === 'light' ? 'terang' : 'gelap'} diaktifkan`);
}

// ---------- STATE ----------
let vaultKey = null;
let vaultSalt = null;
let vaultData = [];
let editingId = null;
let currentFilter = 'all';
let idleTimer = null;
let idleWarningTimer = null;
let searchDebounce = null;
let failedAttempts = 0;
let lockoutUntil = 0;
const IDLE_TIMEOUT = 5 * 60 * 1000;
const IDLE_WARNING = 30 * 1000;
const MAX_ATTEMPTS = 5;
const BASE_LOCKOUT = 30 * 1000;
const totpCache = new Map();
let totpTickerStarted = false;

// ---------- INDEXEDDB ----------
const DB_NAME = 'vaultguard-db';
const DB_VERSION = 2;
const STORE = 'vault';
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function dbGet(k) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readonly');
    const r = tx.objectStore(STORE).get(k);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function dbSet(k, v) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(v, k);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}
async function dbDel(k) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(k);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

// ---------- CRYPTO ----------
function bufToB64(b) {
  const bytes = new Uint8Array(b);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBuf(s) {
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function deriveKey(password, salt, iterations = 600000) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function encryptVault(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data)));
  return { iv: bufToB64(iv), ct: bufToB64(ct) };
}
async function decryptVault(obj, key) {
  const iv = b64ToBuf(obj.iv);
  const ct = b64ToBuf(obj.ct);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(plain));
}

// ---------- UTILS ----------
function showToast(msg, type = 'success') {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast' + (type === 'error' ? ' error' : type === 'warn' ? ' warn' : '');
  t.innerHTML = `<span aria-hidden="true">${type === 'error' ? '❌' : type === 'warn' ? '⚠️' : '✅'}</span> ${escapeHtml(msg)}`;
  c.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0'; t.style.transform = 'translateX(50px)';
    setTimeout(() => t.remove(), 300);
  }, 2800);
}
function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ---------- ENTROPY & STRENGTH ----------
function entropyBits(p) {
  if (!p) return 0;
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/\d/.test(p)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(p)) pool += 32;
  return Math.round(p.length * Math.log2(pool || 1));
}
function passwordStrength(p) {
  const bits = entropyBits(p);
  if (bits < 40) return 'weak';
  if (bits < 70) return 'medium';
  return 'strong';
}
function updateStrengthMeter() {
  const p = document.getElementById('in-pass').value;
  const bits = entropyBits(p);
  const strength = bits < 40 ? 'weak' : bits < 70 ? 'medium' : 'strong';
  const labels = { weak: 'Lemah', medium: 'Sedang', strong: 'Kuat' };
  document.getElementById('strength-label').textContent = labels[strength];
  document.getElementById('entropy-label').textContent = bits + ' bits';
  const filled = Math.min(5, Math.ceil(bits / 20));
  for (let i = 1; i <= 5; i++) {
    const seg = document.getElementById('seg' + i);
    seg.className = 'strength-meter-seg' + (i <= filled ? ' active ' + strength : '');
  }
}

// ---------- IDLE AUTO-LOCK ----------
function resetIdleTimer() {
  clearTimeout(idleTimer);
  clearTimeout(idleWarningTimer);
  document.getElementById('idle-warning').classList.remove('show');
  if (!vaultKey) return;
  idleWarningTimer = setTimeout(() => {
    document.getElementById('idle-warning').classList.add('show');
  }, IDLE_TIMEOUT - IDLE_WARNING);
  idleTimer = setTimeout(() => {
    showToast('Brankas dikunci otomatis', 'warn');
    lockVault();
  }, IDLE_TIMEOUT);
}
['mousemove','keydown','click','scroll','touchstart'].forEach(evt =>
  window.addEventListener(evt, resetIdleTimer, { passive: true })
);

let hiddenTimer = null;
document.addEventListener('visibilitychange', () => {
  if (!vaultKey) return;
  if (document.hidden) {
    hiddenTimer = setTimeout(() => {
      showToast('Brankas dikunci karena tab tidak aktif', 'warn');
      lockVault();
    }, 5000);
  } else {
    clearTimeout(hiddenTimer);
  }
});

// ---------- RATE LIMITING ----------
function isLockedOut() { return Date.now() < lockoutUntil; }
function recordFailure() {
  failedAttempts++;
  if (failedAttempts >= MAX_ATTEMPTS) {
    const backoff = BASE_LOCKOUT * Math.pow(2, failedAttempts - MAX_ATTEMPTS);
    lockoutUntil = Date.now() + backoff;
    const info = document.getElementById('rate-limit-info');
    info.textContent = `Terlalu banyak percobaan. Coba lagi dalam ${Math.ceil(backoff/1000)}s.`;
    setTimeout(() => {
      if (!isLockedOut()) info.textContent = '';
    }, backoff);
  }
}
function resetFailures() { failedAttempts = 0; lockoutUntil = 0; }

// ---------- AUTH ----------
async function checkSetup() {
  const meta = await dbGet('meta');
  if (!meta) {
    document.getElementById('lock-title').textContent = 'Buat Master Password';
    document.getElementById('lock-sub').textContent = 'Tentukan password utama untuk mengenkripsi brankas Anda';
    document.getElementById('confirm-group').style.display = 'block';
    document.getElementById('unlock-btn-text').textContent = 'Buat Brankas';
  }
}
async function unlockVault() {
  if (isLockedOut()) { document.getElementById('auth-error').textContent = 'Terkunci sementara. Tunggu.'; return; }
  const pass = document.getElementById('master-pass').value;
  const errEl = document.getElementById('auth-error');
  errEl.textContent = '';
  if (!pass) { errEl.textContent = 'Master password wajib diisi.'; return; }
  const meta = await dbGet('meta');
  if (!meta) {
    const confirm = document.getElementById('confirm-pass').value;
    if (pass !== confirm) { errEl.textContent = 'Konfirmasi tidak cocok!'; return; }
    if (pass.length < 8) { errEl.textContent = 'Minimal 8 karakter.'; return; }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    vaultSalt = salt;
    vaultKey = await deriveKey(pass, salt);
    vaultData = [];
    await dbSet('meta', { salt: bufToB64(salt), iterations: 600000 });
    await saveVault();
    showApp();
    showToast('Brankas berhasil dibuat');
    return;
  }
  try {
    vaultSalt = b64ToBuf(meta.salt);
    vaultKey = await deriveKey(pass, vaultSalt, meta.iterations);
    const stored = await dbGet('vault');
    vaultData = stored ? await decryptVault(stored, vaultKey) : [];
    resetFailures();
    showApp();
    showToast('Brankas berhasil dibuka');
  } catch (e) {
    recordFailure();
    errEl.textContent = 'Master password salah.';
  }
}
function showApp() {
  document.getElementById('lock-screen').classList.add('hidden');
  document.getElementById('app').classList.add('visible');
  document.getElementById('master-pass').value = '';
  document.getElementById('confirm-pass').value = '';
  document.getElementById('rate-limit-info').textContent = '';
  resetIdleTimer();
  renderList();
  if (!totpTickerStarted) {
    startTotpTicker();
    totpTickerStarted = true;
  }
}
function lockVault() {
  vaultKey = null;
  vaultData = [];
  clearTimeout(idleTimer);
  clearTimeout(idleWarningTimer);
  clearTimeout(hiddenTimer);
  document.getElementById('idle-warning').classList.remove('show');
  document.getElementById('app').classList.remove('visible');
  document.getElementById('lock-screen').classList.remove('hidden');
  document.getElementById('sidebar').classList.remove('open');
  closeModal();
}
async function saveVault() {
  if (!vaultKey) return;
  const enc = await encryptVault(vaultData, vaultKey);
  await dbSet('vault', enc);
}
// ---------- RENDER ----------
function debouncedSearch() {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(renderList, 200);
}
function renderList() {
  const query = (document.getElementById('search-input').value || '').toLowerCase();
  const listEl = document.getElementById('password-list');
  let filtered = vaultData.slice();
  if (query) {
    filtered = filtered.filter(e =>
      (e.site || '').toLowerCase().includes(query) ||
      (e.user || '').toLowerCase().includes(query) ||
      (e.link || '').toLowerCase().includes(query) ||
      (e.note || '').toLowerCase().includes(query) ||
      (e.tags || []).some(t => t.toLowerCase().includes(query))
    );
  }
  if (currentFilter === 'favorite') filtered = filtered.filter(e => e.favorite);
  if (currentFilter === 'strong') filtered = filtered.filter(e => passwordStrength(e.pass) === 'strong');
  if (currentFilter === 'weak') filtered = filtered.filter(e => passwordStrength(e.pass) === 'weak');
  if (currentFilter === 'duplicate') {
    const counts = {};
    vaultData.forEach(e => { counts[e.pass] = (counts[e.pass] || 0) + 1; });
    filtered = filtered.filter(e => counts[e.pass] > 1);
  }
  if (currentFilter === 'old') {
    const oneYear = 365 * 24 * 3600 * 1000;
    filtered = filtered.filter(e => (Date.now() - (e.updated || e.created || 0)) > oneYear);
  }

  const strong = vaultData.filter(e => passwordStrength(e.pass) === 'strong').length;
  const medium = vaultData.filter(e => passwordStrength(e.pass) === 'medium').length;
  const weak = vaultData.filter(e => passwordStrength(e.pass) === 'weak').length;
  document.getElementById('stat-total').textContent = vaultData.length;
  document.getElementById('stat-strong').textContent = strong;
  document.getElementById('stat-medium').textContent = medium;
  document.getElementById('stat-weak').textContent = weak;
  document.getElementById('nav-count').textContent = vaultData.length;
  document.getElementById('nav-weak').textContent = weak;
  document.getElementById('list-count').textContent = filtered.length + ' item';
  const score = vaultData.length
    ? Math.round((strong * 100 + medium * 60 + weak * 20) / vaultData.length)
    : 100;
  document.getElementById('score-num').textContent = score;
  document.getElementById('score-bar').style.width = score + '%';

  const titles = {
    all: 'Kredensial Tersimpan',
    favorite: 'Favorit',
    strong: 'Password Kuat',
    weak: 'Password Lemah',
    duplicate: 'Password Duplikat',
    old: 'Password Lama (>1 tahun)'
  };
  document.getElementById('list-title').textContent = titles[currentFilter];

  if (filtered.length === 0) {
    listEl.innerHTML = `<div class="empty-state"><div class="emoji" aria-hidden="true">🔍</div><p>Tidak ada password ditemukan</p></div>`;
    return;
  }
  const labels = { strong: 'Kuat', medium: 'Sedang', weak: 'Lemah' };
  const oneYear = 365 * 24 * 3600 * 1000;
  listEl.innerHTML = filtered.map((e, i) => {
    const strength = passwordStrength(e.pass);
    const isOld = (Date.now() - (e.updated || e.created || 0)) > oneYear;
    const totpBlock = e.totpSecret ? `
      <div class="totp-container" data-totp-id="${e.id}">
        <span class="totp-code" id="totp-code-${e.id}">······</span>
        <span class="totp-timer" id="totp-timer-${e.id}">30s</span>
        <button class="totp-copy-btn" onclick="copyTotp('${e.id}')" title="Salin kode TOTP">📋</button>
      </div>
      <div class="totp-bar"><div class="totp-bar-fill" id="totp-bar-${e.id}" style="width:100%"></div></div>
    ` : '';
    return `
      <div class="password-item" style="animation-delay:${i*0.04}s">
        <div class="site-icon" style="background:${escapeHtml(e.color || '#4f8cff')}">${escapeHtml(getInitials(e.site))}</div>
        <div class="item-info">
          <div class="site-name">
            ${e.favorite ? '<span class="fav" aria-label="Favorit">★</span>' : ''}
            ${escapeHtml(e.site)}
          </div>
          <div class="username">${escapeHtml(e.user || '—')}</div>
          ${(e.tags && e.tags.length) || isOld || e.breached ? `<div class="tags">
            ${e.breached ? '<span class="tag breached">⚠ Bocor</span>' : ''}
            ${isOld ? '<span class="tag old">⏰ Lama</span>' : ''}
            ${(e.tags || []).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('')}
          </div>` : ''}
          ${totpBlock}
        </div>
        <div class="item-password">••••••••••</div>
        <span class="strength-badge ${strength}">${labels[strength]}</span>
        <div class="item-actions">
          <button class="icon-btn star ${e.favorite ? 'active' : ''}" onclick="toggleFavorite('${e.id}')" title="Favorit" aria-label="Tandai favorit">${e.favorite ? '★' : '☆'}</button>
          <button class="icon-btn" onclick="copyPass('${e.id}')" title="Salin password" aria-label="Salin password">📋</button>
          <button class="icon-btn" onclick="editEntry('${e.id}')" title="Edit" aria-label="Edit">✏️</button>
          <button class="icon-btn danger" onclick="deleteEntry('${e.id}')" title="Hapus" aria-label="Hapus">🗑️</button>
        </div>
      </div>
    `;
  }).join('');
  fillAllTotp();
}
function getInitials(site) {
  return (site || '?').split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
}

// ---------- ACTIONS ----------
async function toggleFavorite(id) {
  const e = vaultData.find(x => x.id === id);
  if (!e) return;
  e.favorite = !e.favorite;
  await saveVault();
  renderList();
}
async function copyPass(id) {
  const e = vaultData.find(x => x.id === id);
  if (!e) return;
  try {
    await navigator.clipboard.writeText(e.pass);
    showToast(`Password ${e.site} disalin (auto-clear 30s)`);
    const pass = e.pass;
    setTimeout(async () => {
      try {
        const cur = await navigator.clipboard.readText();
        if (cur === pass) await navigator.clipboard.writeText('');
      } catch (_) {}
    }, 30000);
  } catch { showToast('Gagal menyalin', 'error'); }
}
async function deleteEntry(id) {
  const e = vaultData.find(x => x.id === id);
  if (!e) return;
  if (!confirm(`Hapus password untuk "${e.site}"?`)) return;
  vaultData = vaultData.filter(x => x.id !== id);
  await saveVault();
  renderList();
  showToast(`Password ${e.site} dihapus`);
}

// ---------- MODAL ----------
function openModal(editId = null) {
  editingId = editId;
  document.getElementById('modal-title').textContent = editId ? 'Edit Password' : 'Tambah Password Baru';
  document.getElementById('in-totp').value = '';
  document.getElementById('totp-preview').style.display = 'none';
  if (!editId) {
    ['in-site','in-link','in-user','in-pass','in-tags','in-note'].forEach(id => document.getElementById(id).value = '');
    updateStrengthMeter();
  }
  document.getElementById('modal').classList.add('open');
  document.getElementById('in-site').focus();
}
function editEntry(id) {
  const e = vaultData.find(x => x.id === id);
  if (!e) return;
  document.getElementById('in-site').value = e.site || '';
  document.getElementById('in-link').value = e.link || '';
  document.getElementById('in-user').value = e.user || '';
  document.getElementById('in-pass').value = e.pass || '';
  document.getElementById('in-tags').value = (e.tags || []).join(', ');
  document.getElementById('in-note').value = e.note || '';
  document.getElementById('in-totp').value = e.totpSecret || '';
  updateStrengthMeter();
  openModal(id);
  if (e.totpSecret) previewTotp();
}
function closeModal() {
  document.getElementById('modal').classList.remove('open');
  editingId = null;
}
function toggleMasterPass(btn) {
  const input = btn.previousElementSibling;
  input.type = input.type === 'password' ? 'text' : 'password';
  btn.textContent = input.type === 'password' ? '👁' : '🙈';
}
function toggleModalPass(btn) {
  const input = btn.previousElementSibling;
  input.type = input.type === 'password' ? 'text' : 'password';
  btn.textContent = input.type === 'password' ? '👁' : '🙈';
}

// ---------- GENERATORS ----------
function generatePassword(len) {
  let chars = 'abcdefghijklmnopqrstuvwxyz';
  if (document.getElementById('opt-upper').checked) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (document.getElementById('opt-numbers').checked) chars += '0123456789';
  if (document.getElementById('opt-symbols').checked) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  if (document.getElementById('opt-exclude').checked) chars = chars.replace(/[0O1lI]/g, '');
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  let p = '';
  for (let i = 0; i < len; i++) p += chars[arr[i] % chars.length];
  document.getElementById('in-pass').value = p;
  document.getElementById('in-pass').type = 'text';
  updateStrengthMeter();
}
const MNEMONIC_THEMES = {
  space: ['Andromeda','Supernova','Exoplanet','Telescope','Asteroid','BlackHole','LightYear','Nebula','Satellite','Quantum'],
  geo: ['Himalaya','Amazonas','Reykjavik','Patagonia','Santorini','Madagascar','Zambezi','Kyoto','Gibraltar','Everest'],
  nature: ['Cheetah','Eucalyptus','Orangutan','Axolotl','Sequoia','Chameleon','Edelweiss','Jellyfish','Flamingo','Piranha'],
  food: ['Espresso','Croissant','Guacamole','Tiramisu','Kimchi','Rendang','Mozzarella','Macarons','Teriyaki','Paella'],
  history: ['Parthenon','Colosseum','TajMahal','MachuPicchu','Pyramids','Stonehenge','Acropolis','Pantheon','Babylon','Alexandria']
};
function generateMnemonic() {
  const themes = Object.keys(MNEMONIC_THEMES);
  const theme = themes[Math.floor(Math.random() * themes.length)];
  const words = MNEMONIC_THEMES[theme];
  let base = words[Math.floor(Math.random() * words.length)];
  base = base.replace(/a/g,'@').replace(/e/g,'3').replace(/i/g,'1').replace(/o/g,'0').replace(/s/g,'$').replace(/t/g,'7');
  const pool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  const rand = new Uint32Array(20);
  crypto.getRandomValues(rand);
  while (base.length < 20) base += pool[rand[base.length] % pool.length];
  document.getElementById('in-pass').value = base.slice(0, 20);
  document.getElementById('in-pass').type = 'text';
  updateStrengthMeter();
  showToast(`Mnemonic (${theme}): ${base.slice(0, 20)}`);
}
const PASSPHRASE_WORDS = ['correct','horse','battery','staple','forest','ocean','mountain','river','cloud','thunder','silent','bright','shadow','crystal','ancient','modern','purple','golden','silver','copper','amber','violet','orange','crimson','azure','emerald','scarlet','ivory','obsidian','marble'];
function generatePassphrase() {
  const arr = new Uint32Array(5);
  crypto.getRandomValues(arr);
  const words = [];
  for (let i = 0; i < 4; i++) words.push(PASSPHRASE_WORDS[arr[i] % PASSPHRASE_WORDS.length]);
  const sep = ['-','_','.','#'][arr[4] % 4];
  const pass = words.join(sep) + '!' + (arr[0] % 100);
  document.getElementById('in-pass').value = pass;
  document.getElementById('in-pass').type = 'text';
  updateStrengthMeter();
  showToast(`Passphrase: ${pass}`);
}
// ---------- TOTP ----------
function generateTotpSecret() {
  try {
    const secret = otplib.generateSecret();
    document.getElementById('in-totp').value = secret;
    showToast('Secret TOTP dibuat. Simpan di authenticator app Anda.');
    previewTotp();
  } catch (e) {
    showToast('Gagal generate secret: ' + e.message, 'error');
  }
}
async function previewTotp() {
  const secret = document.getElementById('in-totp').value.trim();
  const previewEl = document.getElementById('totp-preview');
  if (!secret) { previewEl.style.display = 'none'; return; }
  try {
    const code = await otplib.generate({ secret });
    previewEl.innerHTML = `
      <div class="totp-container">
        <span class="totp-code">${code}</span>
        <span class="totp-timer">30s</span>
      </div>
    `;
    previewEl.style.display = 'block';
  } catch (e) {
    previewEl.style.display = 'none';
    showToast('Secret TOTP tidak valid. Pastikan format Base32.', 'error');
  }
}
function totpSecondsRemaining() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}
async function fillAllTotp() {
  for (const entry of vaultData.filter(e => e.totpSecret)) {
    const codeEl = document.getElementById(`totp-code-${entry.id}`);
    if (!codeEl) continue;
    try {
      const code = await otplib.generate({ secret: entry.totpSecret });
      codeEl.textContent = code;
      totpCache.set(entry.id, code);
    } catch (e) {
      codeEl.textContent = 'ERROR';
      codeEl.style.color = 'var(--danger)';
    }
  }
}
async function copyTotp(entryId) {
  const code = totpCache.get(entryId);
  if (!code) { showToast('Kode TOTP belum siap', 'warn'); return; }
  try {
    await navigator.clipboard.writeText(code);
    showToast('Kode TOTP disalin');
    setTimeout(async () => {
      try {
        const cur = await navigator.clipboard.readText();
        if (cur === code) await navigator.clipboard.writeText('');
      } catch (_) {}
    }, 20000);
  } catch {
    showToast('Gagal menyalin', 'error');
  }
}
function startTotpTicker() {
  setInterval(async () => {
    const entries = vaultData.filter(e => e.totpSecret);
    for (const entry of entries) {
      const codeEl = document.getElementById(`totp-code-${entry.id}`);
      const timerEl = document.getElementById(`totp-timer-${entry.id}`);
      const barEl = document.getElementById(`totp-bar-${entry.id}`);
      if (!codeEl || !timerEl || !barEl) continue;
      try {
        const code = await otplib.generate({ secret: entry.totpSecret });
        const remaining = totpSecondsRemaining();
        const pct = (remaining / 30) * 100;
        if (codeEl.textContent !== code) {
          codeEl.textContent = code;
          totpCache.set(entry.id, code);
        }
        timerEl.textContent = `${remaining}s`;
        const timerClass = remaining <= 5 ? 'danger' : remaining <= 10 ? 'warning' : '';
        codeEl.className = `totp-code ${remaining <= 5 ? 'expired' : ''}`;
        barEl.className = `totp-bar-fill ${timerClass}`;
        barEl.style.width = `${pct}%`;
      } catch (e) {}
    }
  }, 1000);
}

// ---------- SAVE ENTRY ----------
async function saveEntry() {
  const site = document.getElementById('in-site').value.trim();
  const link = document.getElementById('in-link').value.trim();
  const user = document.getElementById('in-user').value.trim();
  const pass = document.getElementById('in-pass').value;
  const note = document.getElementById('in-note').value.trim();
  const tagsRaw = document.getElementById('in-tags').value;
  const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);
  const totpSecret = document.getElementById('in-totp').value.trim();
  if (!site || !pass) { showToast('Nama situs dan password wajib diisi!', 'error'); return; }
  if (totpSecret) {
    try {
      await otplib.generate({ secret: totpSecret });
    } catch (e) {
      showToast('Secret TOTP tidak valid. Periksa format Base32.', 'error');
      return;
    }
  }
  const colors = ['#4f8cff','#7c3aed','#10b981','#f59e0b','#ef4444','#06b6d4','#ec4899'];
  const now = Date.now();
  if (editingId) {
    const idx = vaultData.findIndex(x => x.id === editingId);
    if (idx !== -1) {
      const old = vaultData[idx];
      const history = (old.history || []).slice(-4);
      if (old.pass !== pass) history.push({ pass: old.pass, changed: old.updated || old.created || now });
      vaultData[idx] = { ...old, site, link, user, pass, note, tags, totpSecret, history, updated: now };
    }
  } else {
    vaultData.push({
      id: crypto.randomUUID(),
      site, link, user, pass, note, tags, totpSecret,
      color: colors[Math.floor(Math.random() * colors.length)],
      created: now, updated: now,
      favorite: false, history: []
    });
  }
  await saveVault();
  closeModal();
  renderList();
  showToast(editingId ? `Password ${site} diperbarui` : `Password ${site} disimpan`);
}

// ---------- HIBP ----------
async function sha1Hex(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
async function checkBreach(password) {
  try {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await res.text();
    const lines = text.split('\n');
    for (const line of lines) {
      const [suf, count] = line.split(':');
      if (suf && suf.trim() === suffix) return parseInt(count, 10) || 0;
    }
    return 0;
  } catch (e) {
    return -1;
  }
}
async function checkAllBreaches() {
  if (!vaultData.length) { showToast('Tidak ada password untuk dicek', 'warn'); return; }
  showToast(`Mengecek ${vaultData.length} password di HIBP...`);
  let breachedCount = 0;
  for (const e of vaultData) {
    if (!e.pass) continue;
    const count = await checkBreach(e.pass);
    if (count > 0) {
      e.breached = true;
      breachedCount++;
    } else if (count === 0) {
      e.breached = false;
    }
  }
  await saveVault();
  renderList();
  showToast(
    breachedCount > 0 ? `${breachedCount} password ditemukan di breach publik!` : 'Semua password aman (tidak ada di breach)',
    breachedCount > 0 ? 'error' : 'success'
  );
}

// ---------- EXPORT / IMPORT ----------
async function exportVault() {
  if (!vaultKey) return;
  const enc = await encryptVault(vaultData, vaultKey);
  const payload = {
    version: 2,
    salt: bufToB64(vaultSalt),
    iterations: 600000,
    iv: enc.iv, ct: enc.ct,
    exported: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vaultguard-${new Date().toISOString().slice(0,10)}.vgvault`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Vault diexport (terenkripsi)');
}
async function importVault(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  try {
    const payload = JSON.parse(await file.text());
    if (!payload.salt || !payload.iv || !payload.ct) throw new Error('Format tidak valid');
    const filePass = prompt('Masukkan master password file vault ini:');
    if (!filePass) return;
    const salt = b64ToBuf(payload.salt);
    const fileKey = await deriveKey(filePass, salt, payload.iterations || 600000);
    const data = await decryptVault({ iv: payload.iv, ct: payload.ct }, fileKey);
    if (!Array.isArray(data)) throw new Error('Data tidak valid');
    const merge = confirm(`Ditemukan ${data.length} entri.\nOK = Gabungkan, Cancel = Ganti semua.`);
    if (merge) {
      const ids = new Set(vaultData.map(x => x.id));
      let added = 0;
      data.forEach(e => { if (!ids.has(e.id)) { vaultData.push(e); added++; } });
      showToast(`${added} entri ditambahkan`);
    } else {
      vaultData = data;
      showToast(`${data.length} entri menggantikan vault`);
    }
    await saveVault();
    renderList();
  } catch (err) { showToast('Gagal import: ' + err.message, 'error'); }
  ev.target.value = '';
}
async function importCSV(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) throw new Error('CSV kosong');
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
    const findCol = (...keys) => headers.findIndex(h => keys.some(k => h.includes(k)));
    const idxSite = findCol('site','nama','layanan','title','service');
    const idxUser = findCol('user','email','username','akun');
    const idxPass = findCol('pass','password','sandi');
    const idxLink = findCol('link','url','web','site');
    const idxNote = findCol('note','catatan','hp','phone');
    if (idxSite < 0 || idxPass < 0) throw new Error('Kolom "site/nama" dan "password" wajib ada');
    let added = 0;
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i].match(/("([^"]|"")*"|[^,]*)(,|$)/g)?.map(c => c.replace(/,$/, '').replace(/^"|"$/g, '').replace(/""/g, '"')) || [];
      if (!cols[idxSite] || !cols[idxPass]) continue;
      vaultData.push({
        id: crypto.randomUUID(),
        site: cols[idxSite],
        user: idxUser >= 0 ? cols[idxUser] : '',
        pass: cols[idxPass],
        link: idxLink >= 0 ? cols[idxLink] : '',
        note: idxNote >= 0 ? cols[idxNote] : '',
        tags: [], favorite: false, history: [], totpSecret: '',
        color: '#4f8cff',
        created: Date.now(), updated: Date.now()
      });
      added++;
    }
    await saveVault();
    renderList();
    showToast(`${added} entri diimpor dari CSV`);
  } catch (err) { showToast('Gagal import CSV: ' + err.message, 'error'); }
  ev.target.value = '';
}
async function wipeVault() {
  if (!confirm('HAPUS SEMUA data brankas?')) return;
  if (!confirm('Yakin? Semua password hilang permanen.')) return;
  vaultData = [];
  await saveVault();
  renderList();
  showToast('Semua data dihapus', 'warn');
}

// ---------- NAV FILTER ----------
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter || 'all';
    renderList();
    if (window.innerWidth <= 768) document.getElementById('sidebar').classList.remove('open');
  });
});

// ---------- KEYBOARD ----------
document.getElementById('master-pass').addEventListener('keydown', e => { if (e.key === 'Enter') unlockVault(); });
document.getElementById('confirm-pass').addEventListener('keydown', e => { if (e.key === 'Enter') unlockVault(); });
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    if (vaultKey) document.getElementById('search-input').focus();
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'l' && vaultKey) {
    e.preventDefault();
    lockVault();
  }
});
// ============================================================
// FITUR GANTI MASTER PASSWORD
// ============================================================

function openChangePassModal() {
  document.getElementById('old-pass').value = '';
  document.getElementById('new-pass').value = '';
  document.getElementById('confirm-new-pass').value = '';
  document.getElementById('change-pass-error').textContent = '';
  document.getElementById('change-pass-modal').classList.add('open');
}

function closeChangePassModal() {
  document.getElementById('change-pass-modal').classList.remove('open');
}

async function changeMasterPassword() {
  const oldPass = document.getElementById('old-pass').value;
  const newPass = document.getElementById('new-pass').value;
  const confirmPass = document.getElementById('confirm-new-pass').value;
  const errEl = document.getElementById('change-pass-error');

  errEl.textContent = '';

  if (!oldPass || !newPass || !confirmPass) {
    errEl.textContent = 'Semua kolom wajib diisi!';
    return;
  }

  if (newPass !== confirmPass) {
    errEl.textContent = 'Konfirmasi password baru tidak cocok!';
    return;
  }

  if (newPass.length < 8) {
    errEl.textContent = 'Password baru minimal 8 karakter!';
    return;
  }

  try {
    // 1. Dapatkan meta (salt dan iterasi) yang lama
    const meta = await dbGet('meta');
    if (!meta) throw new Error('Data brankas tidak ditemukan.');

    // 2. Buat kunci lama dan verifikasi dengan cara mendekripsi data
    const oldSalt = b64ToBuf(meta.salt);
    const oldKey = await deriveKey(oldPass, oldSalt, meta.iterations);
    
    // Ambil data terenkripsi saat ini
    const storedData = await dbGet('vault');
    if (!storedData) throw new Error('Vault kosong.');

    let decryptedData;
    try {
      // Tes apakah password lama benar
      decryptedData = await decryptVault(storedData, oldKey);
    } catch (e) {
      // Jika dekripsi gagal, berarti password lama salah
      throw new Error('Master Password lama salah!');
    }

    // 3. Buat kunci baru dan salt baru
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newKey = await deriveKey(newPass, newSalt, 600000);

    // 4. Enkripsi ulang data dengan kunci baru
    const newEncryptedData = await encryptVault(decryptedData, newKey);

    // 5. Simpan meta baru dan data baru ke IndexedDB
    await dbSet('meta', { salt: bufToB64(newSalt), iterations: 600000 });
    await dbSet('vault', newEncryptedData);

    // 6. Perbarui state global (agar enkripsi selanjutnya menggunakan kunci baru)
    vaultKey = newKey;
    vaultSalt = newSalt;

    // 7. Tutup modal dan beri notifikasi
    closeChangePassModal();
    showToast('✅ Master Password berhasil diubah!', 'success');

  } catch (err) {
    errEl.textContent = err.message;
  }
}
// ---------- INIT ----------
window.addEventListener('load', () => {
  initTheme();
  checkSetup();

  // --- DAFTARKAN SERVICE WORKER (FITUR PWA) ---
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then(() => console.log('PWA Service Worker Berhasil Didaftarkan!'))
      .catch((err) => console.log('PWA Gagal:', err));
  }
});