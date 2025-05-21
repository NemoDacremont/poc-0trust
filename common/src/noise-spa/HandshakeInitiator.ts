import assert from "assert";
import { HASH_NAME, PROLOGUE, PROTOCOL_NAME } from "./constants";
import { KeyPair } from "./KeyPair";
import { SPA } from "./SPA";
import { SymmetricState } from "./SymmetricState";
import { dh, Key } from "./utils";

export interface HandshakeInitiatorOptions {
  s: KeyPair;
  rs: Key;
  psk: Key;
}

function getTimestampBuffer(): Buffer {
  const timestamp = Math.floor(Date.now() / 1000);
  const buffer = Buffer.alloc(8);

  buffer.writeBigInt64LE(BigInt(timestamp));
  return buffer;
}

export class HandshakeInitiator {
  private ss: SymmetricState;
  private s: KeyPair;
  private rs: Key;
  private psk: Key;
  private e: KeyPair | null;
  private re: Key | null;

  constructor({ s, rs, psk }: HandshakeInitiatorOptions) {
    this.ss = new SymmetricState(PROTOCOL_NAME, HASH_NAME);

    this.s = s;
    this.rs = rs;
    this.psk = psk;
    this.e = null;
    this.re = null;

    this.ss.mixHash(Buffer.from(PROLOGUE, "utf-8"));
    this.ss.mixHash(this.rs);
  }

  writeMessageA(payload: Buffer): SPA {
    this.e = KeyPair.generate();

    this.ss.mixHash(this.e.getPublic());
    this.ss.mixKey(this.e.getPublic());
    this.ss.mixKey(dh(this.e.getPrivate(), this.rs));

    const v = Buffer.concat([getTimestampBuffer(), this.s.getPublic()]);
    const nv = this.ss.encryptAndHash(v);

    const shared2 = dh(this.s.getPrivate(), this.rs);
    this.ss.mixKey(shared2);
    this.ss.mixKeyAndHash(this.psk);

    const nm = this.ss.encryptAndHash(payload);
    return new SPA(this.e.getPublic(), nv, nm);
  }

  readMessageB(messageB: Buffer): Buffer {
    assert(
      this.ss !== null,
      "readMessageA should have initialized the SymmetricState.",
    );
    assert(
      this.e !== null,
      "readMessageA should have initialized the ephemeral keys.",
    );

    const spa = SPA.unpack(messageB);
    this.re = spa.getKey();

    this.ss.mixHash(this.re);
    this.ss.mixKey(this.re);

    this.ss.mixKey(dh(this.e.getPrivate(), this.re));
    this.ss.mixKey(dh(this.s.getPrivate(), this.re));

    const plaintext = this.ss.decryptAndHash(spa.getCiphertext());
    return plaintext;
  }
}
