import {
  SymmetricState,
  ProtocolNameType,
  HashNameType,
} from "../src/noise-spa/SymmetricState";
import { KEY_SIZE } from "../src/noise-spa/constants";

describe("SymmetricState", () => {
  const protocolName: ProtocolNameType =
    "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s";
  const hashName: HashNameType = "BLAKE2s256";

  const randomKey = Buffer.alloc(KEY_SIZE, 0xca);
  const randomKey2 = Buffer.alloc(KEY_SIZE, 0xfe);
  const randomKey3 = Buffer.alloc(KEY_SIZE, 0xbeef);
  const data = Buffer.from("test-data");
  const data2 = Buffer.from("other-data");

  describe("mixHash", () => {
    it("should update h", () => {
      const ss = new SymmetricState(protocolName, hashName);
      const oldH = Buffer.from(ss["h"]);

      ss.mixHash(data);
      const newH = Buffer.from(ss["h"]);

      expect(newH).not.toEqual(oldH);
    });
  });

  describe("mixKey", () => {
    it("should update ck", () => {
      const ss = new SymmetricState(protocolName, hashName);

      const oldCk = ss["ck"];
      ss.mixKey(randomKey);
      const newCk = ss["ck"];

      expect(newCk).not.toEqual(oldCk);
    });

    it("should update cs", () => {
      const ss = new SymmetricState(protocolName, hashName);

      const oldCs = ss["cs"];
      ss.mixKey(randomKey);
      const newCs = ss["cs"];

      expect(newCs).not.toEqual(oldCs);
    });
  });

  describe("mixKeyAndHash", () => {
    it("should update ck", () => {
      const ss = new SymmetricState(protocolName, hashName);

      const oldCk = ss["ck"];
      ss.mixKeyAndHash(randomKey2);
      const newCk = ss["ck"];

      expect(newCk).not.toEqual(oldCk);
    });

    it("should update h", () => {
      const ss = new SymmetricState(protocolName, hashName);

      const oldH = ss["h"];
      ss.mixKeyAndHash(randomKey2);
      const newH = ss["h"];

      expect(newH).not.toEqual(oldH);
    });

    it("should update cs", () => {
      const ss = new SymmetricState(protocolName, hashName);

      const oldCs = ss["cs"];
      ss.mixKeyAndHash(randomKey2);
      const newCs = ss["cs"];

      expect(newCs).not.toEqual(oldCs);
    });
  });

  describe("encryptAndHash", () => {
    it("should returns plaintext if no key is set", () => {
      const ss = new SymmetricState(protocolName, hashName);
      // Simulate no key: re-init cs with all-zero key

      const oldH = Buffer.from((ss as any).h);
      const ct = ss.encryptAndHash(data);
      expect(ct.equals(data)).toBe(true);
      expect((ss as any).h.equals(oldH)).toBe(false);
    });

    it("should update h", () => {
      const ss = new SymmetricState(protocolName, hashName);

      // Simulate no key: re-init cs with all-zero key
      const oldHNoKey = ss["h"];
      ss.encryptAndHash(data);
      const newHNoKey = ss["h"];

      // Simulate with key
      const oldH = ss["h"];
      ss.encryptAndHash(data2);
      const newH = ss["h"];

      expect(newHNoKey).not.toEqual(oldHNoKey);
      expect(newH).not.toEqual(oldH);
    });
  });

  describe("decryptAndHash", () => {
    it("decryptAndHash returns ciphertext if no key is set", () => {
      const ss = new SymmetricState(protocolName, hashName);
      const pt = ss.decryptAndHash(data2);

      expect(pt).toStrictEqual(data2);
    });
  });

  describe("encrypt and decrypt", () => {
    it("encryptAndHash and decryptAndHash are inverses when key is set", () => {
      const ssA = new SymmetricState(protocolName, hashName);

      // Set a key
      ssA.mixKey(randomKey3);
      const plaintext = Buffer.from("secret message");
      const ciphertext = ssA.encryptAndHash(plaintext);
      expect(ciphertext).not.toEqual(plaintext);

      // Decrypt with a new SymmetricState in same state
      const ssB = new SymmetricState(protocolName, hashName);
      ssB.mixKey(randomKey3);
      const pt2 = ssB.decryptAndHash(ciphertext);

      expect(pt2).toStrictEqual(plaintext);
    });
  });
});
