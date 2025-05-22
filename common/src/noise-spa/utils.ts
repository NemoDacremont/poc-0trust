import { x25519 } from "@noble/curves/ed25519";
import { KEY_SIZE } from "./constants";
import assert from "assert";
import { InvalidKeySizeError } from "./exceptions";

export type Key = Buffer;

// Diffie-Hellman
export function dh(privateKey: Key, publicKey: Key): Key {
  assert(
    privateKey.byteLength === KEY_SIZE,
    new InvalidKeySizeError(KEY_SIZE, privateKey.byteLength),
  );
  assert(
    publicKey.byteLength === KEY_SIZE,
    new InvalidKeySizeError(KEY_SIZE, publicKey.byteLength),
  );

  return Buffer.from(x25519.getSharedSecret(privateKey, publicKey));
}
