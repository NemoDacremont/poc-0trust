import { randomBytes } from "crypto";
import { KEY_SIZE } from "../src/noise-spa/constants";
import { dh } from "../src/noise-spa/utils";
import { x25519 } from "@noble/curves/ed25519";
import { InvalidKeySizeError } from "../src/noise-spa/exceptions";

describe("dh (Diffie-Hellman/X25519)", () => {
  it("computes the same shared secret for both parties", () => {
    const alicePrivate = randomBytes(KEY_SIZE);
    const bobPrivate = randomBytes(KEY_SIZE);
    const alicePublic = Buffer.from(x25519.getPublicKey(alicePrivate));
    const bobPublic = Buffer.from(x25519.getPublicKey(bobPrivate));

    const aliceSecret = dh(alicePrivate, bobPublic);
    const bobSecret = dh(bobPrivate, alicePublic);

    expect(aliceSecret.equals(bobSecret)).toBe(true);
    expect(aliceSecret.length).toBe(KEY_SIZE);
  });

  it("throws InvalidKeySizeError for invalid private key size", () => {
    const publicKey = randomBytes(KEY_SIZE);

    for (let keySize = 0; keySize < KEY_SIZE; keySize++) {
      const badPrivate = Buffer.alloc(keySize);

      expect(() => dh(badPrivate, publicKey)).toThrow(
        new InvalidKeySizeError(KEY_SIZE, keySize),
      );
    }
  });

  it("throws InvalidKeySizeError for invalid public key size", () => {
    const privateKey = randomBytes(KEY_SIZE);

    for (let keySize = 0; keySize < KEY_SIZE; keySize++) {
      const badPublic = Buffer.alloc(keySize);

      expect(() => dh(privateKey, badPublic)).toThrow(
        new InvalidKeySizeError(KEY_SIZE, keySize),
      );
    }
  });

  it("is symmetric: dh(a, B) === dh(b, A)", () => {
    const a = Buffer.from(randomBytes(KEY_SIZE));
    const b = Buffer.from(randomBytes(KEY_SIZE));
    const A = Buffer.from(x25519.getPublicKey(a));
    const B = Buffer.from(x25519.getPublicKey(b));

    expect(dh(a, B).equals(dh(b, A))).toBe(true);
  });

  it("should match RFC 7748 X25519 test vector", () => {
    // RFC 7748 test vector https://www.rfc-editor.org/rfc/rfc7748.html page 13
    const alicePrivate = Buffer.from(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      "hex",
    );
    const bobPublic = Buffer.from(
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      "hex",
    );
    const expectedSecret = Buffer.from(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
      "hex",
    );

    const secret = dh(alicePrivate, bobPublic);
    expect(secret).toStrictEqual(expectedSecret);
  });
});
