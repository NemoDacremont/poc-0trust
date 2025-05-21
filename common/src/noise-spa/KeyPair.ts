import { randomBytes } from "crypto";
import { Key } from "./utils";
import { x25519 } from "@noble/curves/ed25519";
import { KEY_SIZE } from "./constants";
import assert from "assert";
import { InvalidKeySizeError } from "./exceptions/InvalidKeySizeError";

export class KeyPair {
  private public: Key;
  private private: Key;

  static generate(): KeyPair {
    const privateKey = randomBytes(KEY_SIZE);
    return KeyPair.fromPrivate(privateKey);
  }

  static fromPrivate(privateKey: Key): KeyPair {
    assert(
      privateKey.byteLength === KEY_SIZE,
      new InvalidKeySizeError(KEY_SIZE, privateKey.byteLength),
    );

    const publicKey = Buffer.from(x25519.getPublicKey(privateKey));
    return new KeyPair(publicKey, privateKey);
  }

  constructor(publicKey: Key, privateKey: Key) {
    assert(
      publicKey.byteLength === KEY_SIZE,
      new InvalidKeySizeError(KEY_SIZE, publicKey.byteLength),
    );
    assert(
      privateKey.byteLength === KEY_SIZE,
      new InvalidKeySizeError(KEY_SIZE, privateKey.byteLength),
    );

    this.public = publicKey;
    this.private = privateKey;
  }

  getPublic(): Key {
    return this.public;
  }
  getPrivate(): Key {
    return this.private;
  }
}
