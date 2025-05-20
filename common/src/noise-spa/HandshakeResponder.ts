import {
  HASH_NAME,
  PROLOGUE,
  PROTOCOL_NAME,
  TIMESTAMP_SIZE,
} from "./constants";
import { KeyPair } from "./KeyPair";
import { SPA } from "./SPA";
import { SymmetricState } from "./SymmetricState";
import { dh, Key } from "./utils";

export interface HandshakeResponderOptions {
  s: KeyPair;
}

export class HandshakeResponder {
  private s: KeyPair;

  // Can be null if the commands aren't used in the right order
  private ss: SymmetricState | null;
  private rs: Key | null;
  private psk: Key | null;

  constructor({ s }: HandshakeResponderOptions) {
    this.s = s;

    this.ss = null;
    this.rs = null;
    this.psk = null;
  }

  readMessageA(
    messageA: Buffer,
    getPSKByID: (rs: Key) => Key | null,
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
