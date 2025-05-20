import { createCipheriv, createDecipheriv } from "crypto";
import { EMPTY_KEY, MIN_NONCE, TAG_SIZE } from "./constants";
import { Key } from "./utils";

export function createCipher(key: Key, nonce: Key) {
  return createCipheriv("chacha20-poly1305", key, nonce);
}

export function createDecipher(key: Key, nonce: Key) {
  return createDecipheriv("chacha20-poly1305", key, nonce);
}

export class CipherState {
  private key: Key;
  private nonce: number;

  constructor(k: Key) {
    this.key = k;
    this.nonce = MIN_NONCE;
  }

  hasKey(): boolean {
    return EMPTY_KEY.compare(this.key) !== 0;
  }

  encrypt(ad: Buffer, plaintext: Buffer): Buffer {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64LE(BigInt(this.nonce), 4);

    const cipher = createCipher(this.key, nonce);
    cipher.setAAD(ad, { plaintextLength: Buffer.byteLength(plaintext) });

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    this.nonce++;
    return ciphertext;
  }

  decrypt(ad: Buffer, ciphertext: Buffer): Buffer {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64LE(BigInt(this.nonce), 4);
    const cipher = createDecipher(this.key, nonce);

    const encrypted = ciphertext.subarray(0, -TAG_SIZE);
    const tag = ciphertext.subarray(-TAG_SIZE);

    cipher.setAuthTag(tag);
    cipher.setAAD(ad, { plaintextLength: Buffer.byteLength(encrypted) });

    const decrypted = Buffer.concat([cipher.update(encrypted), cipher.final()]);

    this.nonce++;
    return decrypted;
  }
}
