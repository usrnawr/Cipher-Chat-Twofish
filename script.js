
// ============================================================
// TWOFISH CBC — IMPLEMENTASI FROM SCRATCH (JavaScript ES6+)
// Tanpa library kriptografi eksternal
// ============================================================

// ---- MDS Matrix ----
const MDS = [
  [0x01, 0xEF, 0x5B, 0x5B],
  [0x5B, 0xEF, 0xEF, 0x01],
  [0xEF, 0x5B, 0x01, 0xEF],
  [0xEF, 0x01, 0xEF, 0x5B]
];

// ---- RS Matrix ----
const RS = [
  [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
  [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
  [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
  [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03]
];

// ---- q0 and q1 S-box permutations ----
const q0 = [
  0xA9,0x67,0xB3,0xE8,0x04,0xFD,0xA3,0x76,0x9A,0x92,0x80,0x78,0xE4,0xDD,0xD1,0x38,
  0x0D,0xC6,0x35,0x98,0x18,0xF7,0xEC,0x6C,0x43,0x75,0x37,0x26,0xFA,0x13,0x94,0x48,
  0xF2,0xD0,0x8B,0x30,0x84,0x54,0xDF,0x23,0x19,0x5B,0x3D,0x59,0xF3,0xAE,0xA2,0x82,
  0x63,0x01,0x83,0x2E,0xD9,0x51,0x9B,0x7C,0xA6,0xEB,0xA5,0xBE,0x16,0x0C,0xE3,0x61,
  0xC0,0x8C,0x3A,0xF5,0x73,0x2C,0x25,0x0B,0xBB,0x4E,0x89,0x6B,0x53,0x6A,0xB4,0xF1,
  0xE1,0xE6,0xBD,0x45,0xE2,0xF4,0xB6,0x66,0xCC,0x95,0x03,0x56,0xD4,0x1C,0x1E,0xD7,
  0xFB,0xC3,0x8E,0xB5,0xE9,0xCF,0xBF,0xBA,0xEA,0x77,0x39,0xAF,0x33,0xC9,0x62,0x71,
  0x81,0x79,0x09,0xAD,0x24,0xCD,0xF9,0xD8,0xE5,0xC5,0xB9,0x4D,0x44,0x08,0x86,0xE7,
  0xA1,0x1D,0xAA,0xED,0x06,0x70,0xB2,0xD2,0x41,0x7B,0xA0,0x11,0x31,0xC2,0x27,0x90,
  0x20,0xF6,0x60,0xFF,0x96,0x5C,0xB1,0xAB,0x9E,0x9C,0x52,0x1B,0x5F,0x93,0x0A,0xEF,
  0x91,0x85,0x49,0xEE,0x2D,0x4F,0x8F,0x3B,0x47,0x87,0x6D,0x46,0xD6,0x3E,0x69,0x64,
  0x2A,0xCE,0xCB,0x2F,0xFC,0x97,0x05,0x7A,0xAC,0x7F,0xD5,0x1A,0x4B,0x0E,0xA7,0x5A,
  0x28,0x14,0x3F,0x29,0x88,0x3C,0x4C,0x02,0xB8,0xDA,0xB0,0x17,0x55,0x1F,0x8A,0x7D,
  0x57,0xC7,0x8D,0x74,0xB7,0xC4,0x9F,0x72,0x7E,0x15,0x22,0x12,0x58,0x07,0x99,0x34,
  0x6E,0x50,0xDE,0x68,0x65,0xBC,0xDB,0xF8,0xC8,0xA8,0x2B,0x40,0xDC,0xFE,0x32,0xA4,
  0xCA,0x10,0x21,0xF0,0xD3,0x5D,0x0F,0x00,0x6F,0x9D,0x36,0x42,0x4A,0x5E,0xC1,0xE0
];

const q1 = [
  0x75,0xF3,0xC6,0xF4,0xDB,0x7B,0xFB,0xC8,0x4A,0xD3,0xE6,0x6B,0x45,0x7D,0xE8,0x4B,
  0xD6,0x32,0xD8,0xFD,0x37,0x71,0xF1,0xE1,0x30,0x0F,0xF8,0x1B,0x87,0xFA,0x06,0x3F,
  0x5E,0xBA,0xAE,0x5B,0x8A,0x00,0xBC,0x9D,0x6D,0xC1,0xB1,0x0E,0x80,0x5D,0xD2,0xD5,
  0xA0,0x84,0x07,0x14,0xB5,0x90,0x2C,0xA3,0xB2,0x73,0x4C,0x54,0x92,0x74,0x36,0x51,
  0x38,0xB0,0xBD,0x5A,0xFC,0x60,0x62,0x96,0x6C,0x42,0xF7,0x10,0x7C,0x28,0x27,0x8C,
  0x13,0x95,0x9C,0xC7,0x24,0x46,0x3B,0x70,0xCA,0xE3,0x85,0xCB,0x11,0xD0,0x93,0xB8,
  0xA6,0x83,0x20,0xFF,0x9F,0x77,0xC3,0xCC,0x03,0x6F,0x08,0xBF,0x40,0xE7,0x2B,0xE2,
  0x79,0x0C,0xAA,0x82,0x41,0x3A,0xEA,0xB9,0xE4,0x9A,0xA4,0x97,0x7E,0xDA,0x7A,0x17,
  0x66,0x94,0xA1,0x1D,0x3D,0xF0,0xDE,0xB3,0x0B,0x72,0xA7,0x1C,0xEF,0xD1,0x53,0x3E,
  0x8F,0x33,0x26,0x5F,0xEC,0x76,0x2A,0x49,0x81,0x88,0xEE,0x21,0xC4,0x1A,0xEB,0xD9,
  0xC5,0x39,0x99,0xCD,0xAD,0x31,0x8B,0x01,0x18,0x23,0xDD,0x1F,0x4E,0x2D,0xF9,0x48,
  0x4F,0xF2,0x65,0x8E,0x78,0x5C,0x58,0x19,0x8D,0xE5,0x98,0x57,0x67,0x7F,0x05,0x64,
  0xAF,0x63,0xB6,0xFE,0xF5,0xB7,0x3C,0xA5,0xCE,0xE9,0x68,0x44,0xE0,0x4D,0x43,0x69,
  0x29,0x2E,0xAC,0x15,0x59,0xA8,0x0A,0x9E,0x6E,0x47,0xDF,0x34,0x35,0x6A,0xCF,0xDC,
  0x22,0xC9,0xC0,0x9B,0x89,0xD4,0xED,0xAB,0x12,0xA2,0x0D,0x52,0xBB,0x02,0x2F,0xA9,
  0xD7,0x61,0x1E,0xB4,0x50,0x04,0xF6,0xC2,0x16,0x25,0x86,0x56,0x55,0x09,0xBE,0x91
];

// ---- GF(2^8) multiplication ----
function gfMul(a, b, poly) {
  let result = 0;
  while (b > 0) {
    if (b & 1) result ^= a;
    a <<= 1;
    if (a & 0x100) a ^= poly;
    b >>= 1;
  }
  return result & 0xFF;
}

// ---- MDS multiply ----
function mdsMul(vector) {
  const result = new Array(4).fill(0);
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      result[i] ^= gfMul(MDS[i][j], vector[j], 0x169);
    }
  }
  return result;
}

// ---- q permutation ----
function qPerm(x, q) {
  return q[x & 0xFF];
}

// ---- h function ----
function hFunc(x, M, keySize) {
  let y = [x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF];

  if (keySize >= 32) {
    y[0] = qPerm(y[0] ^ (M[12] & 0xFF), q1);
    y[1] = qPerm(y[1] ^ ((M[12] >> 8) & 0xFF), q0);
    y[2] = qPerm(y[2] ^ ((M[12] >> 16) & 0xFF), q0);
    y[3] = qPerm(y[3] ^ ((M[12] >> 24) & 0xFF), q1);
    y[0] = qPerm(y[0] ^ (M[14] & 0xFF), q1);
    y[1] = qPerm(y[1] ^ ((M[14] >> 8) & 0xFF), q1);
    y[2] = qPerm(y[2] ^ ((M[14] >> 16) & 0xFF), q0);
    y[3] = qPerm(y[3] ^ ((M[14] >> 24) & 0xFF), q0);
  }
  if (keySize >= 24) {
    y[0] = qPerm(y[0] ^ (M[8] & 0xFF), q1);
    y[1] = qPerm(y[1] ^ ((M[8] >> 8) & 0xFF), q0);
    y[2] = qPerm(y[2] ^ ((M[8] >> 16) & 0xFF), q1);
    y[3] = qPerm(y[3] ^ ((M[8] >> 24) & 0xFF), q0);
    y[0] = qPerm(y[0] ^ (M[10] & 0xFF), q0);
    y[1] = qPerm(y[1] ^ ((M[10] >> 8) & 0xFF), q1);
    y[2] = qPerm(y[2] ^ ((M[10] >> 16) & 0xFF), q0);
    y[3] = qPerm(y[3] ^ ((M[10] >> 24) & 0xFF), q1);
  }

  y[0] = qPerm(y[0] ^ (M[4] & 0xFF), q0);
  y[1] = qPerm(y[1] ^ ((M[4] >> 8) & 0xFF), q1);
  y[2] = qPerm(y[2] ^ ((M[4] >> 16) & 0xFF), q0);
  y[3] = qPerm(y[3] ^ ((M[4] >> 24) & 0xFF), q1);
  y[0] = qPerm(y[0] ^ (M[6] & 0xFF), q1);
  y[1] = qPerm(y[1] ^ ((M[6] >> 8) & 0xFF), q0);
  y[2] = qPerm(y[2] ^ ((M[6] >> 16) & 0xFF), q1);
  y[3] = qPerm(y[3] ^ ((M[6] >> 24) & 0xFF), q0);

  y[0] = qPerm(y[0] ^ (M[0] & 0xFF), q1);
  y[1] = qPerm(y[1] ^ ((M[0] >> 8) & 0xFF), q0);
  y[2] = qPerm(y[2] ^ ((M[0] >> 16) & 0xFF), q1);
  y[3] = qPerm(y[3] ^ ((M[0] >> 24) & 0xFF), q0);
  y[0] = qPerm(y[0] ^ (M[2] & 0xFF), q0);
  y[1] = qPerm(y[1] ^ ((M[2] >> 8) & 0xFF), q1);
  y[2] = qPerm(y[2] ^ ((M[2] >> 16) & 0xFF), q1);
  y[3] = qPerm(y[3] ^ ((M[2] >> 24) & 0xFF), q0);

  const mds = mdsMul(y);
  return (mds[0] & 0xFF) | ((mds[1] & 0xFF) << 8) | ((mds[2] & 0xFF) << 16) | ((mds[3] & 0xFF) << 24);
}

// ---- Rotate left / right (32-bit) ----
function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

// ---- Key Schedule ----
function keySchedule(keyBytes) {
  const keySize = keyBytes.length;
  const Nw = keySize / 4;

  // Build M array (words)
  const M = new Array(Nw).fill(0);
  for (let i = 0; i < Nw; i++) {
    M[i] = (keyBytes[i*4] | (keyBytes[i*4+1] << 8) |
            (keyBytes[i*4+2] << 16) | (keyBytes[i*4+3] << 24)) >>> 0;
  }

  // Build Me and Mo
  const Me = [], Mo = [];
  for (let i = 0; i < Nw/2; i++) {
    Me.push(M[2*i]);
    Mo.push(M[2*i+1]);
  }

  // Generate subkeys
  const K = new Array(40).fill(0);
  const rho = 0x01010101;
  for (let i = 0; i < 20; i++) {
    const A = hFunc(rotl32(2*i * rho, 0), Me, keySize);
    const B = rotl32(hFunc(rotl32((2*i+1) * rho, 8), Mo, keySize), 8);
    K[2*i]   = (A + B) >>> 0;
    K[2*i+1] = rotl32((A + 2*B) >>> 0, 9);
  }

  return { K, M, keySize };
}

// ---- F function ----
function fFunc(R0, R1, K, r, M, keySize) {
  const T0 = hFunc(R0, M, keySize);
  const T1 = hFunc(rotl32(R1, 8), M, keySize);
  const F0 = (T0 + T1 + K[2*r + 8]) >>> 0;
  const F1 = (T0 + 2*T1 + K[2*r + 9]) >>> 0;
  return [F0, F1];
}

// ---- Encrypt one 128-bit block ----
function encryptBlock(block, K, M, keySize) {
  let R = [
    ((block[0]  | (block[1]  << 8) | (block[2]  << 16) | (block[3]  << 24)) >>> 0) ^ K[0],
    ((block[4]  | (block[5]  << 8) | (block[6]  << 16) | (block[7]  << 24)) >>> 0) ^ K[1],
    ((block[8]  | (block[9]  << 8) | (block[10] << 16) | (block[11] << 24)) >>> 0) ^ K[2],
    ((block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24)) >>> 0) ^ K[3]
  ];

  for (let r = 0; r < 16; r++) {
    const [F0, F1] = fFunc(R[0], R[1], K, r, M, keySize);
    const tmp0 = rotr32(R[2] ^ F0, 1);
    const tmp1 = rotl32(R[3], 1) ^ F1;
    R = [tmp0, tmp1, R[0], R[1]];
  }

  return [
    R[2] ^ K[4], R[3] ^ K[5], R[0] ^ K[6], R[1] ^ K[7]
  ].flatMap(w => [w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF]);
}

// ---- Decrypt one 128-bit block ----
function decryptBlock(block, K, M, keySize) {
  // Undo output whitening: encryptBlock output adalah [R2^K4, R3^K5, R0^K6, R1^K7]
  // Jadi: R[0]=word2^K6, R[1]=word3^K7, R[2]=word0^K4, R[3]=word1^K5
  let R = [
    ((block[8]  | (block[9]  << 8) | (block[10] << 16) | (block[11] << 24)) >>> 0) ^ K[6],
    ((block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24)) >>> 0) ^ K[7],
    ((block[0]  | (block[1]  << 8) | (block[2]  << 16) | (block[3]  << 24)) >>> 0) ^ K[4],
    ((block[4]  | (block[5]  << 8) | (block[6]  << 16) | (block[7]  << 24)) >>> 0) ^ K[5]
  ];

  for (let r = 15; r >= 0; r--) {
    const [F0, F1] = fFunc(R[2], R[3], K, r, M, keySize);
    const tmp2 = rotl32(R[0], 1) ^ F0;
    const tmp3 = rotr32(R[1] ^ F1, 1);
    R = [R[2], R[3], tmp2, tmp3];
  }

  return [
    R[0] ^ K[0], R[1] ^ K[1], R[2] ^ K[2], R[3] ^ K[3]
  ].flatMap(w => [w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF]);
}

// ---- PKCS7 Padding ----
function pkcs7Pad(data) {
  const padLen = 16 - (data.length % 16);
  return [...data, ...new Array(padLen).fill(padLen)];
}

function pkcs7Unpad(data) {
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > 16) throw new Error('Padding tidak valid');
  return data.slice(0, data.length - padLen);
}

// ---- Generate IV ----
function generateIV() {
  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  return Array.from(iv);
}

// ---- CBC Encrypt ----
function cbcEncrypt(plaintext, keyBytes) {
  const { K, M, keySize } = keySchedule(keyBytes);
  const padded = pkcs7Pad(plaintext);
  const iv = generateIV();
  let prev = iv;
  const ciphertext = [];

  const numBlocks = padded.length / 16;
  for (let i = 0; i < numBlocks; i++) {
    const block = padded.slice(i * 16, i * 16 + 16);
    const xored = block.map((b, j) => b ^ prev[j]);
    const enc = encryptBlock(xored, K, M, keySize);
    ciphertext.push(...enc);
    prev = enc;
  }

  return { ciphertext: [...iv, ...ciphertext], subkeys: K, numBlocks };
}

// ---- CBC Decrypt ----
function cbcDecrypt(ciphertext, keyBytes) {
  if (ciphertext.length < 32 || (ciphertext.length % 16) !== 0)
    throw new Error('Ciphertext tidak valid');

  const { K, M, keySize } = keySchedule(keyBytes);
  const iv = ciphertext.slice(0, 16);
  const data = ciphertext.slice(16);
  let prev = iv;
  const plaintext = [];

  const numBlocks = data.length / 16;
  for (let i = 0; i < numBlocks; i++) {
    const block = data.slice(i * 16, i * 16 + 16);
    const dec = decryptBlock(block, K, M, keySize);
    plaintext.push(...dec.map((b, j) => b ^ prev[j]));
    prev = block;
  }

  return { plaintext: pkcs7Unpad(plaintext), subkeys: K, numBlocks };
}

// ---- String/Bytes helpers ----
function strToBytes(str) {
  return Array.from(new TextEncoder().encode(str));
}

function bytesToStr(bytes) {
  return new TextDecoder().decode(new Uint8Array(bytes));
}

function bytesToHex(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  hex = hex.replace(/\s/g, '');
  if (hex.length % 2 !== 0) throw new Error('Hex tidak valid');
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

function padKey(keyStr, targetLen) {
  const bytes = strToBytes(keyStr);
  if (bytes.length >= targetLen) return bytes.slice(0, targetLen);
  const padded = [...bytes];
  while (padded.length < targetLen) padded.push(0);
  return padded;
}

// ---- UI State ----
let currentMode = 'encrypt';
let currentKeySize = 16;
let lastSubkeys = [];

function setMode(mode) {
  currentMode = mode;
  document.getElementById('btnEncMode').classList.toggle('active', mode === 'encrypt');
  document.getElementById('btnDecMode').classList.toggle('active', mode === 'decrypt');
  document.getElementById('labelInput').textContent = mode === 'encrypt' ? 'PLAINTEXT' : 'CIPHERTEXT (HEX)';
  document.getElementById('btnText').textContent = mode === 'encrypt' ? '🔒 Enkripsi Pesan' : '🔓 Dekripsi Pesan';
  document.getElementById('outputLabel').textContent = mode === 'encrypt' ? 'OUTPUT — CIPHERTEXT' : 'OUTPUT — PLAINTEXT';
  document.getElementById('inputText').placeholder = mode === 'encrypt'
    ? 'Masukkan pesan yang ingin dienkripsi...'
    : 'Paste ciphertext (hex) di sini...';
  document.getElementById('outputBox').innerHTML = '<span class="output-empty">Hasil akan tampil di sini...</span>';
  clearStatus('processStatus');
}

function setKeySize(size, btn) {
  currentKeySize = size;
  document.querySelectorAll('.key-opt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  validateKey();
}

function validateKey() {
  const key = document.getElementById('keyInput').value;
  const keyBytes = strToBytes(key);
  const statusEl = document.getElementById('keyStatus');
  if (!key) { clearStatus('keyStatus'); return false; }
  if (keyBytes.length < currentKeySize) {
    setStatus('keyStatus', `⚠ Kunci ${keyBytes.length} byte — akan dipadding ke ${currentKeySize} byte`, 'info');
    return true;
  }
  if (keyBytes.length > currentKeySize) {
    setStatus('keyStatus', `⚠ Kunci ${keyBytes.length} byte — akan dipotong ke ${currentKeySize} byte`, 'info');
    return true;
  }
  setStatus('keyStatus', `✓ Kunci valid: ${keyBytes.length} byte (${currentKeySize * 8}-bit)`, 'success');
  return true;
}

function setStatus(id, msg, type) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.className = `status-bar ${type}`;
}

function clearStatus(id) {
  const el = document.getElementById(id);
  el.className = 'status-bar';
}

function toggleVis() {
  const show = document.getElementById('visCheck').checked;
  document.getElementById('visPanel').classList.toggle('show', show);
}

function initRoundGrid() {
  const grid = document.getElementById('roundGrid');
  grid.innerHTML = '';
  for (let i = 1; i <= 16; i++) {
    const cell = document.createElement('div');
    cell.className = 'round-cell';
    cell.id = `round-${i}`;
    cell.textContent = `R${i}`;
    grid.appendChild(cell);
  }
}

function animateRounds(numBlocks) {
  if (!document.getElementById('visCheck').checked) return;
  initRoundGrid();
  let r = 1;
  const interval = setInterval(() => {
    if (r > 16) { clearInterval(interval); return; }
    document.getElementById(`round-${r}`)?.classList.add('active');
    if (r > 1) {
      const prev = document.getElementById(`round-${r-1}`);
      prev?.classList.remove('active');
      prev?.classList.add('done');
    }
    r++;
  }, 80);
  setTimeout(() => {
    document.getElementById(`round-16`)?.classList.remove('active');
    document.getElementById(`round-16`)?.classList.add('done');
  }, 80 * 17);
}

function showSubkeys(subkeys) {
  if (!document.getElementById('visCheck').checked) return;
  const el = document.getElementById('keyDisplay');
  el.innerHTML = subkeys.map((k, i) =>
    `<div class="subkey-cell">K[${i}]<br/>${(k >>> 0).toString(16).padStart(8,'0').toUpperCase()}</div>`
  ).join('');
}

function copyOutput() {
  const text = document.getElementById('outputBox').innerText;
  if (text && !text.includes('Hasil akan tampil')) {
    navigator.clipboard.writeText(text).then(() => {
      setStatus('processStatus', '✓ Berhasil disalin ke clipboard!', 'success');
      setTimeout(() => clearStatus('processStatus'), 2000);
    });
  }
}

async function process() {
  const inputText = document.getElementById('inputText').value.trim();
  const keyStr = document.getElementById('keyInput').value;

  if (!inputText) { setStatus('processStatus', '✗ Masukkan teks terlebih dahulu!', 'error'); return; }
  if (!keyStr)    { setStatus('processStatus', '✗ Masukkan kunci terlebih dahulu!', 'error'); return; }

  const btn = document.getElementById('btnProcess');
  const btnText = document.getElementById('btnText');
  btn.disabled = true;
  btnText.innerHTML = `<span class="spinner"></span>Memproses...`;

  await new Promise(r => setTimeout(r, 50));

  try {
    const keyBytes = padKey(keyStr, currentKeySize);
    const outputEl = document.getElementById('outputBox');

    if (currentMode === 'encrypt') {
      const plain = strToBytes(inputText);
      const { ciphertext, subkeys, numBlocks } = cbcEncrypt(plain, keyBytes);
      const hex = bytesToHex(ciphertext);
      outputEl.textContent = hex;
      outputEl.style.color = 'var(--accent)';
      setStatus('processStatus',
        `✓ Berhasil dienkripsi! ${plain.length} byte → ${ciphertext.length} byte (${numBlocks} blok + IV 16 byte)`, 'success');
      animateRounds(numBlocks);
      showSubkeys(subkeys);

    } else {
      const cipherBytes = hexToBytes(inputText);
      const { plaintext, subkeys, numBlocks } = cbcDecrypt(cipherBytes, keyBytes);
      const result = bytesToStr(plaintext);
      outputEl.textContent = result;
      outputEl.style.color = 'var(--success)';
      setStatus('processStatus',
        `✓ Berhasil didekripsi! ${cipherBytes.length} byte → ${plaintext.length} byte (${numBlocks} blok)`, 'success');
      animateRounds(numBlocks);
      showSubkeys(subkeys);
    }

  } catch (e) {
    setStatus('processStatus', `✗ Error: ${e.message}`, 'error');
    document.getElementById('outputBox').innerHTML = '<span class="output-empty">Proses gagal.</span>';
  } finally {
    btn.disabled = false;
    btnText.innerHTML = currentMode === 'encrypt' ? '🔒 Enkripsi Pesan' : '🔓 Dekripsi Pesan';
  }
}

// ---- Init ----
document.getElementById('keyInput').addEventListener('input', validateKey);
initRoundGrid();
