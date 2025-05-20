import { createPrivateKey, createPublicKey, diffieHellman } from "crypto";
import {
  HASH_NAME,
  PROLOGUE,
  PROTOCOL_NAME,
  TIMESTAMP_SIZE,
} from "./constants";
import { KeyPair } from "./KeyPair";
import { SPA } from "./SPA";
import { SymmetricState } from "./SymmetricState";

export interface HandshakeResponderOptions {
  s: KeyPair;
}

function dh(privateKey: Buffer, publicKey: Buffer) {
  // Create a Diffie-Hellman key exchange object using X25519
  const sharedSecret = diffieHellman({
    privateKey: createPrivateKey({
      key: privateKey,
      format: "der",
      type: "pkcs8",
    }),
    publicKey: createPublicKey({ key: publicKey, format: "der", type: "spki" }),
  });

  return sharedSecret;
}

export class HandshakeResponder {
  private s: KeyPair;

  // Can be null if the commands aren't used in the right order
  private ss: SymmetricState | null;
  private rs: Buffer | null;
  private psk: Buffer | null;

  constructor({ s }: HandshakeResponderOptions) {
    this.ss = null;

    this.s = s;
    this.rs = null;
    this.psk = null;
  }

  readMessageA(
    messageA: Buffer,
    getPSKByID: (rs: Buffer) => Buffer | null,
  ): { timestamp: Buffer; plaintext: Buffer } {
    const spa = SPA.unpack(messageA);

    this.ss = new SymmetricState(PROTOCOL_NAME, HASH_NAME);

    this.ss.mixHash(Buffer.from(PROLOGUE, "utf-8"));
    this.ss.mixHash(this.s.getPublic());

    // TODO: Validate public key

    this.ss.mixHash(spa.getKey());
    this.ss.mixKey(spa.getKey());
    this.ss.mixKey(dh(this.s.getPrivate(), spa.getKey()));

    let decrypted;
    try {
      // valid1 = ...
      decrypted = this.ss.decryptAndHash(spa.getValue());
    } catch (error) {
      throw new Error("Decryption of client data failed.");
    }

    // Extract timestamp and rs from decrypted data
    const timestamp = decrypted.subarray(0, TIMESTAMP_SIZE);
    this.rs = decrypted.subarray(TIMESTAMP_SIZE);

    this.psk = getPSKByID(this.rs);
    if (this.psk === null)
      throw new Error(`Unknown client <${this.rs.toString("hex")}>`);

    this.ss.mixKey(dh(this.s.getPrivate(), this.rs));
    this.ss.mixKeyAndHash(this.psk);

    // Valid2 = ...
    const plaintext = this.ss.decryptAndHash(spa.getCiphertext());
    return { timestamp, plaintext };
  }

  writeMessageB(plaintext: Buffer): Buffer {
    return Buffer.from("gitgud");
  }
}
