export const PROLOGUE = "SPA_by_ThaySan_avecungrospadding";
export const PROTOCOL_NAME = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s";
export const CURVE_NAME = "x25519";
export const HASH_NAME = "BLAKE2s256";
export const CIPHER_NAME = "CHACHA20-POLY1305";
export const MIN_NONCE = 0;
export const KEY_SIZE = 32;
export const PSK_SIZE = 32;
export const TAG_SIZE = 16;

export const EMPTY_KEY = Buffer.alloc(KEY_SIZE);

// Modified protocol
export const TIMESTAMP_SIZE = 8;
export const NV_SIZE = TIMESTAMP_SIZE + KEY_SIZE + TAG_SIZE;
