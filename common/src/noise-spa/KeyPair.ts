import { randomBytes } from "crypto";
import { Key } from "./utils";
import { x25519 } from "@noble/curves/ed25519";
import { KEY_SIZE } from "./constants";

export class KeyPair {
  private public: Key;
  private private: Key;

  static generate(keySize = KEY_SIZE): KeyPair {
    const privateKey = randomBytes(keySize);
    return KeyPair.fromPrivate(privateKey);
  }

  static fromPrivate(privateKey: Key): KeyPair {
    const publicKey = Buffer.from(x25519.getPublicKey(privateKey));
    return new KeyPair(publicKey, privateKey);
  }

  constructor(publicKey: Key, privateKey: Key) {
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
