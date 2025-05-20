import { createECDH, generateKeyPairSync, KeyObject } from "crypto";

export class KeyPair {
  private public: Buffer;
  private private: Buffer;

  static generate(): KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("x25519");
    return new KeyPair(publicKey, privateKey);
  }

  static fromPrivate(sk: Buffer): KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("x25519", {
      privateKey: sk,
    });
    return new KeyPair(publicKey, privateKey);
  }

  constructor(publicKey: KeyObject, privateKey: KeyObject) {
    this.public = publicKey.export({ format: "der", type: "spki" });
    this.private = privateKey.export({ format: "der", type: "pkcs8" });
  }

  getPublic(): Buffer {
    return this.public;
  }
  getPrivate(): Buffer {
    return this.private;
  }
}
