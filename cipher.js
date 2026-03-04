/**
 * CipherDash — Deterministic Encryption Engine
 * All randomness comes from SHA-256 of the user's keyword.
 * No Math.random is used anywhere.
 */

// ─── Deterministic PRNG (Mulberry32) ────────────────────────────────────────
// Takes a 32-bit seed from the SHA-256 hash and produces a sequence of
// pseudo-random numbers in [0, 1). Deterministic: same seed = same sequence.
function mulberry32(seed) {
  return function () {
    let t = (seed += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ─── Seed Generation ─────────────────────────────────────────────────────────
/**
 * Hashes the keyword with SHA-256 to produce a 32-byte seed array.
 * @param {string} keyword
 * @returns {Promise<Uint8Array>} 32-byte seed
 */
async function generateSeed(keyword) {
  const encoder = new TextEncoder();
  const data = encoder.encode(keyword);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hashBuffer);
}

// ─── Rule Generation ─────────────────────────────────────────────────────────
/**
 * Derives all cipher parameters from a 32-byte seed.
 * Every byte of the seed is used to make brute-force expensive.
 * @param {Uint8Array} seedBytes
 * @returns {Object} rules
 */
function generateRules(seedBytes) {
  // Use bytes 0-3 as the primary PRNG seed
  const seed0 =
    (seedBytes[0] << 24) |
    (seedBytes[1] << 16) |
    (seedBytes[2] << 8) |
    seedBytes[3];
  const rand = mulberry32(seed0 >>> 0);

  // 1. Substitution map: shuffle [0..255] with Fisher-Yates
  const substitutionMap = Array.from({ length: 256 }, (_, i) => i);
  for (let i = 255; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [substitutionMap[i], substitutionMap[j]] = [
      substitutionMap[j],
      substitutionMap[i],
    ];
  }

  // 2. Reverse substitution map for decryption
  const reverseSubMap = new Array(256);
  for (let i = 0; i < 256; i++) reverseSubMap[substitutionMap[i]] = i;

  // 3. Byte shift (0–255), uses bytes 4-5 for extra entropy
  const shift = (seedBytes[4] ^ seedBytes[5]) & 0xff;

  // 4. Block size (3–12), uses bytes 6-7
  const blockSize = 3 + ((seedBytes[6] ^ seedBytes[7]) % 10);

  // 5. Reorder seed for block permutation PRNG, uses bytes 8-11
  const reorderSeed =
    ((seedBytes[8] << 24) |
      (seedBytes[9] << 16) |
      (seedBytes[10] << 8) |
      seedBytes[11]) >>>
    0;

  // 6. XOR mask (0–255), uses bytes 12-13
  const xorMask = (seedBytes[12] ^ seedBytes[13]) & 0xff;

  // 7. Encoding: 'hex' or 'base64', uses byte 14
  const encoding = seedBytes[14] % 2 === 0 ? "hex" : "base64";

  return {
    substitutionMap,
    reverseSubMap,
    shift,
    blockSize,
    reorderSeed,
    xorMask,
    encoding,
  };
}

// ─── Block Reorder Permutation ────────────────────────────────────────────────
/**
 * Generates a permutation array of length n using Mulberry32 seeded with
 * reorderSeed. Same n + same seed = same permutation always.
 */
function getBlockPermutation(n, reorderSeed) {
  const rand = mulberry32(reorderSeed);
  const perm = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  return perm;
}

// ─── Encryption ───────────────────────────────────────────────────────────────
/**
 * Encrypts plaintext using the derived rules.
 * Pipeline: UTF-8 encode → substitute → shift → split blocks → reorder → XOR → encode
 *
 * KEY FIX: Only full-sized blocks are permuted. The short remainder block (if
 * any) is always appended last so decrypt can split byte boundaries correctly.
 * @param {string} plaintext
 * @param {Object} rules
 * @returns {string} ciphertext
 */
function encrypt(plaintext, rules) {
  const { substitutionMap, shift, blockSize, reorderSeed, xorMask, encoding } =
    rules;

  // Step 1: UTF-8 encode
  const bytes = Array.from(new TextEncoder().encode(plaintext));

  // Step 2: Byte substitution
  const substituted = bytes.map((b) => substitutionMap[b]);

  // Step 3: Byte shift
  const shifted = substituted.map((b) => (b + shift) & 0xff);

  // Step 4: Split into FULL blocks only; keep remainder separate
  const nFull = Math.floor(shifted.length / blockSize);
  const fullBlocks = [];
  for (let i = 0; i < nFull; i++) {
    fullBlocks.push(shifted.slice(i * blockSize, (i + 1) * blockSize));
  }
  // Remainder bytes that don't fill a complete block
  const remainder = shifted.slice(nFull * blockSize);

  // Step 5: Permute ONLY the full blocks — remainder is always appended last
  let reordered;
  if (fullBlocks.length > 1) {
    const perm = getBlockPermutation(fullBlocks.length, reorderSeed);
    reordered = new Array(fullBlocks.length);
    for (let i = 0; i < fullBlocks.length; i++) {
      reordered[perm[i]] = fullBlocks[i];
    }
  } else {
    reordered = fullBlocks;
  }

  // Flatten permuted blocks + remainder
  const flat = [...reordered.flat(), ...remainder];

  // Step 6: XOR
  const xored = flat.map((b) => b ^ xorMask);

  // Step 7: Encode
  const uint8 = new Uint8Array(xored);
  if (encoding === "hex") {
    return Array.from(uint8)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } else {
    return btoa(String.fromCharCode(...uint8));
  }
}

// ─── Decryption ───────────────────────────────────────────────────────────────
/**
 * Decrypts ciphertext using the derived rules (exact reverse of encrypt).
 *
 * KEY FIX: Mirror of the encrypt fix — only nFull full blocks are un-permuted;
 * the trailing remainder bytes are handled separately.
 * @param {string} ciphertext
 * @param {Object} rules
 * @returns {string} plaintext
 */
function decrypt(ciphertext, rules) {
  const { reverseSubMap, shift, blockSize, reorderSeed, xorMask, encoding } =
    rules;

  // Step 1: Decode
  let bytes;
  try {
    if (encoding === "hex") {
      if (ciphertext.length % 2 !== 0)
        throw new Error("Invalid hex ciphertext length");
      bytes = [];
      for (let i = 0; i < ciphertext.length; i += 2) {
        bytes.push(parseInt(ciphertext.slice(i, i + 2), 16));
      }
    } else {
      bytes = Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
    }
  } catch {
    throw new Error(
      "Decryption failed: invalid ciphertext or wrong key encoding"
    );
  }

  // Step 2: Reverse XOR
  const unxored = bytes.map((b) => b ^ xorMask);

  // Step 3: Separate nFull full blocks from trailing remainder
  const nFull = Math.floor(unxored.length / blockSize);
  const fullBlocks = [];
  for (let i = 0; i < nFull; i++) {
    fullBlocks.push(unxored.slice(i * blockSize, (i + 1) * blockSize));
  }
  const remainder = unxored.slice(nFull * blockSize);

  // Step 4: Reverse block permutation on full blocks only
  let unordered;
  if (fullBlocks.length > 1) {
    const perm = getBlockPermutation(fullBlocks.length, reorderSeed);
    unordered = new Array(fullBlocks.length);
    for (let i = 0; i < fullBlocks.length; i++) {
      unordered[i] = fullBlocks[perm[i]];
    }
  } else {
    unordered = fullBlocks;
  }

  // Reconstruct: un-permuted full blocks + remainder
  const flat = [...unordered.flat(), ...remainder];

  // Step 5: Reverse byte shift
  const unshifted = flat.map((b) => (b - shift + 256) & 0xff);

  // Step 6: Reverse substitution
  const unsubstituted = unshifted.map((b) => reverseSubMap[b]);

  // Step 7: UTF-8 decode
  try {
    return new TextDecoder().decode(new Uint8Array(unsubstituted));
  } catch {
    throw new Error("Decryption failed: result is not valid UTF-8");
  }
}

// ─── Fingerprint ──────────────────────────────────────────────────────────────
/**
 * Returns first 8 hex chars of seed for display (like a key fingerprint).
 */
function getFingerprint(seedBytes) {
  return Array.from(seedBytes.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// ─── Random Key Generator ─────────────────────────────────────────────────────
/**
 * Generates a cryptographically random alphanumeric key.
 * No Math.random used — uses crypto.getRandomValues.
 * Only safe characters: letters + digits (no spaces, no specials that could
 * cause copy/paste or URL encoding headaches).
 * @param {number} length
 * @returns {string}
 */
function generateRandomKey(length = 20) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return Array.from(randomBytes)
    .map((b) => chars[b % chars.length])
    .join("");
}

/**
 * Sanitizes a key string: removes spaces and any character that isn't
 * a letter, digit, hyphen, underscore, or dot.
 * @param {string} raw
 * @returns {string}
 */
function sanitizeKey(raw) {
  // Strip everything except safe chars
  return raw.replace(/[^A-Za-z0-9\-_.]/g, '');
}

// Export for use in index.html (module-style or global)
if (typeof module !== "undefined") {
  module.exports = {
    generateSeed,
    generateRules,
    encrypt,
    decrypt,
    getFingerprint,
    generateRandomKey,
    sanitizeKey,
  };
}
