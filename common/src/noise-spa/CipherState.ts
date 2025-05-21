import { createCipheriv, createDecipheriv } from "crypto";
import { EMPTY_KEY, KEY_SIZE, MIN_NONCE, TAG_SIZE } from "./constants";
import { Key } from "./utils";
import assert from "assert";
import { InvalidKeySizeError } from "./exceptions/InvalidKeySizeError";

export class CipherState {
  private key: Key;
  private nonce: number;

  private static createCipher(key: Key, nonce: Key) {
    return createCipheriv("chacha20-poly1305", key, nonce);
  }

  private static createDecipher(key: Key, nonce: Key) {
    return createDecipheriv("chacha20-poly1305", key, nonce);
  }

  constructor(k: Key) {
    assert(
      k.byteLength == KEY_SIZE,
      new InvalidKeySizeError(KEY_SIZE, k.byteLength),
    );
    this.key = k;
    this.nonce = MIN_NONCE;
  }

  hasKey(): boolean {
    return EMPTY_KEY.compare(this.key) !== 0;
  }

  encrypt(ad: Buffer, plaintext: Buffer): Buffer {
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64LE(BigInt(this.nonce), 4);

    const cipher = CipherState.createCipher(this.key, nonce);
    cipher.setAAD(ad, { plaintextLength: plaintext.byteLength });

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
    const cipher = CipherState.createDecipher(this.key, nonce);

    const realCiphertext = ciphertext.subarray(0, -TAG_SIZE);
    const tag = ciphertext.subarray(-TAG_SIZE);

    cipher.setAuthTag(tag);
    cipher.setAAD(ad, { plaintextLength: realCiphertext.byteLength });

    const plaintext = Buffer.concat([
      cipher.update(realCiphertext),
      cipher.final(),
    ]);

    this.nonce++;
    return plaintext;
  }
}
