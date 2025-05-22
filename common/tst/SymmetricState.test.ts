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
  const plaintext = Buffer.from("53cR37_M3s54G3");

  describe("mixHash", () => {
    it("should update h", () => {
      const ss = new SymmetricState(protocolName, hashName);
      const oldH = ss["h"];

      ss.mixHash(data);
      const newH = ss["h"];

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

      const ct = ss.encryptAndHash(data);
      expect(ct).toStrictEqual(data);
    });

    it("should returns ciphertext after a mixKey", () => {
      const ss = new SymmetricState(protocolName, hashName);

      ss.mixKey(randomKey2);

      const ct = ss.encryptAndHash(data);
      expect(ct).not.toEqual(data);
    });

    it("should returns ciphertext after many operations", () => {
      const ss = new SymmetricState(protocolName, hashName);

      ss.mixKey(randomKey2);
      ss.mixHash(data2);
      ss.mixKeyAndHash(randomKey3);
      ss.mixHash(data);
      ss.mixKey(randomKey2);

      const ct = ss.encryptAndHash(data);
      expect(ct).not.toEqual(data);
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
    it("returns ciphertext if no key is set", () => {
      const ss = new SymmetricState(protocolName, hashName);
      const pt = ss.decryptAndHash(data2);

      expect(pt).toStrictEqual(data2);
    });

    it("fails to decipher if incorrect payload and not in init state", () => {
      const ss = new SymmetricState(protocolName, hashName);
      ss.mixKey(randomKey2);

      expect(() => ss.decryptAndHash(data2)).toThrow();
    });

    it("fails to decipher if incorrect payload and in complex state", () => {
      const ss = new SymmetricState(protocolName, hashName);

      ss.mixKey(randomKey2);
      ss.mixKey(randomKey2);
      ss.mixHash(data2);
      ss.mixKeyAndHash(randomKey3);
      ss.mixHash(data);

      expect(() => ss.decryptAndHash(data2)).toThrow();
    });
  });

  describe("encrypt and decrypt", () => {
    it("encrypt and decrypt if using the same mixKey", () => {
      const ssA = new SymmetricState(protocolName, hashName);

      // Set a key
      ssA.mixKey(randomKey3);
      const ciphertext = ssA.encryptAndHash(plaintext);
      expect(ciphertext).not.toEqual(plaintext);

      // Decrypt with a new SymmetricState in same state
      const ssB = new SymmetricState(protocolName, hashName);
      ssB.mixKey(randomKey3);
      const pt2 = ssB.decryptAndHash(ciphertext);

      expect(pt2).toStrictEqual(plaintext);
    });

    it("encrypt and decrypt if using the same mixHash", () => {
      const ssA = new SymmetricState(protocolName, hashName);

      ssA.mixHash(randomKey2);
      const ciphertext = ssA.encryptAndHash(plaintext);

      const ssB = new SymmetricState(protocolName, hashName);
      ssB.mixHash(randomKey2);
      const pt2 = ssB.decryptAndHash(ciphertext);

      // Since the key is not init using mixKey or mixKeyAndHash, the plaintext
      // is not altered
      expect(pt2).toStrictEqual(plaintext);
      expect(pt2).toStrictEqual(ciphertext);
    });

    it("encrypt and decrypt if using the same mixKeyAndHash", () => {
      const ssA = new SymmetricState(protocolName, hashName);

      ssA.mixKeyAndHash(randomKey);
      const ciphertext = ssA.encryptAndHash(plaintext);
      expect(ciphertext).not.toEqual(plaintext);

      const ssB = new SymmetricState(protocolName, hashName);
      ssB.mixKeyAndHash(randomKey);
      const pt2 = ssB.decryptAndHash(ciphertext);

      expect(pt2).toStrictEqual(plaintext);
    });

    it("encrypt and decrypt if in the same complex state", () => {
      const ssA = new SymmetricState(protocolName, hashName);

      ssA.mixKey(randomKey2);
      ssA.mixKeyAndHash(randomKey);
      ssA.mixKey(randomKey2);
      ssA.mixHash(data2);
      ssA.mixKeyAndHash(randomKey3);
      ssA.mixHash(data);
      const ciphertext = ssA.encryptAndHash(plaintext);
      expect(ciphertext).not.toEqual(plaintext);

      const ssB = new SymmetricState(protocolName, hashName);
      ssB.mixKey(randomKey2);
      ssB.mixKeyAndHash(randomKey);
      ssB.mixKey(randomKey2);
      ssB.mixHash(data2);
      ssB.mixKeyAndHash(randomKey3);
      ssB.mixHash(data);
      const pt2 = ssB.decryptAndHash(ciphertext);

      expect(pt2).toStrictEqual(plaintext);
    });
  });
});
