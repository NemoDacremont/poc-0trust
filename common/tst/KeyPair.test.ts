import { randomBytes } from "crypto";
import { KeyPair } from "../src";
import { KEY_SIZE } from "../src/noise-spa/constants";
import { InvalidKeySizeError } from "../src/noise-spa/exceptions/InvalidKeySizeError";
import { x25519 } from "@noble/curves/ed25519";

describe("KeyPair", () => {
  const validPrivateKey = Buffer.alloc(KEY_SIZE, 0x42);
  const validPublicKey = Buffer.alloc(KEY_SIZE, 0x24);

  describe("getters", () => {
    it("returns the correct public and private keys", () => {
      const keyPair = new KeyPair(validPublicKey, validPrivateKey);

      expect(keyPair.getPublic()).toStrictEqual(validPublicKey);
      expect(keyPair.getPrivate()).toStrictEqual(validPrivateKey);
    });
  });

  describe("generate", () => {
    it("generates a valid KeyPair", () => {
      const keyPair = KeyPair.generate();

      expect(keyPair.getPublic().byteLength).toBe(KEY_SIZE);
      expect(keyPair.getPrivate().byteLength).toBe(KEY_SIZE);
    });

    it("generates a correct KeyPair", () => {
      const keyPair = KeyPair.generate();
      const expectedPublicKey = x25519.getPublicKey(keyPair.getPrivate());

      expect(keyPair.getPublic()).toStrictEqual(expectedPublicKey);
    });
  });

  describe("fromPrivate", () => {
    it("creates a valid KeyPair from a valid private key", () => {
      const keyPair = KeyPair.fromPrivate(validPrivateKey);

      expect(keyPair.getPublic().byteLength).toBe(KEY_SIZE);
      expect(keyPair.getPrivate().byteLength).toBe(KEY_SIZE);
    });

    it("creates a the right KeyPair from a valid private key", () => {
      const keyPair = KeyPair.fromPrivate(validPrivateKey);
      const expectedPublicKey = x25519.getPublicKey(validPrivateKey);

      expect(keyPair.getPrivate()).toStrictEqual(validPrivateKey);
      expect(keyPair.getPublic()).toStrictEqual(expectedPublicKey);
    });

    it("throws InvalidKeySizeError for invalid private key size", () => {
      for (let keySize = 0; keySize < KEY_SIZE; keySize++) {
        const invalidPrivateKey = Buffer.alloc(keySize);
        const invalidRandomPrivateKey = randomBytes(keySize);

        expect(() => KeyPair.fromPrivate(invalidPrivateKey)).toThrow(
          new InvalidKeySizeError(KEY_SIZE, keySize),
        );
        expect(() => KeyPair.fromPrivate(invalidRandomPrivateKey)).toThrow(
          new InvalidKeySizeError(KEY_SIZE, keySize),
        );
      }
    });
  });

  describe("constructor", () => {
    it("constructs with valid keys", () => {
      expect(new KeyPair(validPublicKey, validPrivateKey)).not.toThrow();
    });

    it("creates a KeyPair with valid public and private keys", () => {
      const keyPair = new KeyPair(validPublicKey, validPrivateKey);

      expect(keyPair.getPublic().byteLength).toBe(KEY_SIZE);
      expect(keyPair.getPrivate().byteLength).toBe(KEY_SIZE);
    });

    it("throws InvalidKeySizeError for invalid public key size", () => {
      for (let keySize = 0; keySize < KEY_SIZE; keySize++) {
        const invalidPublicKey = Buffer.alloc(keySize);
        const invalidRandomPublicKey = randomBytes(keySize);

        expect(() => new KeyPair(invalidPublicKey, validPrivateKey)).toThrow(
          new InvalidKeySizeError(KEY_SIZE, keySize),
        );
        expect(
          () => new KeyPair(invalidRandomPublicKey, validPrivateKey),
        ).toThrow(new InvalidKeySizeError(KEY_SIZE, keySize));
      }
    });

    it("throws InvalidKeySizeError for invalid private key size", () => {
      for (let keySize = 0; keySize < KEY_SIZE; keySize++) {
        const invalidPrivateKey = Buffer.alloc(keySize);
        const invalidRandomPrivateKey = randomBytes(keySize);

        expect(() => new KeyPair(validPublicKey, invalidPrivateKey)).toThrow(
          new InvalidKeySizeError(KEY_SIZE, keySize),
        );
        expect(
          () => new KeyPair(validPublicKey, invalidRandomPrivateKey),
        ).toThrow(new InvalidKeySizeError(KEY_SIZE, keySize));
      }
    });

    it("throws InvalidKeySizeError for invalid public and private key size", () => {
      for (let pKeySize = 0; pKeySize < KEY_SIZE; pKeySize++) {
        const invalidPublicKey = Buffer.alloc(pKeySize);
        const invalidRandomPublicKey = randomBytes(pKeySize);

        for (let sKeySize = 0; sKeySize < KEY_SIZE; sKeySize++) {
          const invalidPrivateKey = Buffer.alloc(sKeySize);
          const invalidRandomPrivateKey = randomBytes(sKeySize);

          expect(
            () => new KeyPair(invalidPublicKey, invalidPrivateKey),
          ).toThrow(InvalidKeySizeError);
          expect(
            () => new KeyPair(invalidPublicKey, invalidRandomPrivateKey),
          ).toThrow(InvalidKeySizeError);
          expect(
            () => new KeyPair(invalidRandomPublicKey, invalidPrivateKey),
          ).toThrow(InvalidKeySizeError);
          expect(
            () => new KeyPair(invalidRandomPublicKey, invalidRandomPrivateKey),
          ).toThrow(InvalidKeySizeError);
        }
      }
    });
  });
});
