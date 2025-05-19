import { createPrivateKey, createPublicKey, diffieHellman, KeyObject } from "crypto";
import { HASH_NAME, PROLOGUE, PROTOCOL_NAME } from "./constants";
import { KeyPair } from "./KeyPair"
import { SPA } from "./SPA";
import { SymmetricState } from "./SymmetricState"


export interface HandshakeOptions {
  s: KeyPair;
  rs: Buffer;
  psk: Buffer;
}


function dh(privateKey: Buffer, publicKey: Buffer) {
    // Create a Diffie-Hellman key exchange object using X25519
    const sharedSecret = diffieHellman({
        privateKey: createPrivateKey({key: privateKey, format: "der", type: "pkcs8"}),
        publicKey: createPublicKey({key: publicKey, format: "der", type: "spki"}),
    });

    return sharedSecret;
}


function getTimestampBuffer(): Buffer {
  const timestamp = Math.floor(Date.now() / 1000)
  const buffer = Buffer.alloc(8)

  buffer.writeBigInt64LE(BigInt(timestamp))
  return buffer
}


export class Handshake {
  private ss: SymmetricState;
  private s: KeyPair;
  private rs: Buffer;
  private psk: Buffer;

  constructor({ s, rs, psk }: HandshakeOptions) {
    this.ss = new SymmetricState(PROTOCOL_NAME, HASH_NAME)
    this.s = s
    this.rs = rs
    this.psk = psk
    this.ss.mixHash(Buffer.from(PROLOGUE, 'utf-8'))
    this.ss.mixHash(this.rs)
  }

  prepare(message: Buffer): SPA {
    const e = KeyPair.generate()

    this.ss.mixHash(e.getPublic())
    this.ss.mixKey(e.getPublic())
    this.ss.mixKey(dh(e.getPrivate(), this.rs))

    const v = Buffer.concat([getTimestampBuffer(), this.s.getPublic()])
    const nv = this.ss.encryptAndHash(v)

    this.ss.mixKey(dh(this.s.getPrivate(), this.rs))
    this.ss.mixKeyAndHash(this.psk)

    const nm = this.ss.encryptAndHash(message)
    return new SPA(e.getPublic(), nv, nm)
  }

  static handle({data, s, getSPKbyID}: HandshakeHandleOptions) {}
}

