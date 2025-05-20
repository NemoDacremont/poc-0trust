import { x25519 } from "@noble/curves/ed25519";

export type Key = Buffer;

// Diffie-Hellman
export function dh(privateKey: Key, publicKey: Key): Key {
  return Buffer.from(x25519.getSharedSecret(privateKey, publicKey));
}
