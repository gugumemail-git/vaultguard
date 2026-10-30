import { test, expect } from 'vitest';

// Kita perlu mengimpor fungsi dari app.js.
// Karena app.js menggunakan variabel global (vaultKey, dll), kita harus berhati-hati.
// Untuk tes ini, kita akan menguji logika inti enkripsi secara terpisah.
// Di produksi, Anda sebaiknya memisahkan fungsi kripto ke file modul sendiri (misal: crypto.js).

test('Enkripsi dan Dekripsi berhasil dengan kunci yang benar', async () => {
  // 1. Siapkan data dummy
  const originalData = [{ id: '1', site: 'Test', pass: 'rahasia123' }];
  
  // 2. Buat kunci dummy (di app.js asli ini diturunkan dari master password)
  // Kita gunakan fungsi deriveKey yang ada di app.js (pastikan bisa diakses)
  // Untuk mempermudah tes, kita bisa membuat kunci langsung di sini:
  const enc = new TextEncoder();
  const rawKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // 3. Enkripsi
  // Kita tiru logika encryptVault dari app.js
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    rawKey,
    enc.encode(JSON.stringify(originalData))
  );

  // 4. Dekripsi
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    rawKey,
    ciphertext
  );
  const decryptedData = JSON.parse(new TextDecoder().decode(decryptedBuffer));

  // 5. Pastikan hasilnya sama
  expect(decryptedData).toEqual(originalData);
});

test('Dekripsi GAGAL jika kunci salah', async () => {
  const originalData = 'Data Rahasia';
  const enc = new TextEncoder();
  
  const key1 = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const key2 = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); // Kunci berbeda

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key1, enc.encode(originalData));

  // Mencoba mendekripsi dengan key2 harus melempar error
  await expect(async () => {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key2, ciphertext);
  }).rejects.toThrow();
});