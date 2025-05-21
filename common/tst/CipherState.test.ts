import { CipherState } from "../src/noise-spa/CipherState";
import { InvalidKeySizeError } from "../src/noise-spa/exceptions/InvalidKeySizeError";
import { EMPTY_KEY, KEY_SIZE, TAG_SIZE } from "../src/noise-spa/constants";
import { randomBytes } from "crypto";
import { x25519 } from "@noble/curves/ed25519";

describe("CipherState", () => {
  // Example test values
  const TEST_KEY = Buffer.alloc(KEY_SIZE, 0xdeadbeefcafe);
  const TEST_AD = Buffer.from("associated data");
  const TEST_PLAINTEXT = Buffer.from("hello world");
  const TEST_EMPTY_KEY = Buffer.alloc(KEY_SIZE, 0x00);

  it("constructs with a valid key", () => {
    expect(() => new CipherState(TEST_KEY)).not.toThrow();
  });

  it("throws InvalidKeySizeError with an invalid key", () => {
    for (let keySize = 0; keySize < KEY_SIZE; ++keySize) {
      const invalidKey = randomBytes(keySize);
      expect(() => new CipherState(invalidKey)).toThrow(
        new InvalidKeySizeError(KEY_SIZE, keySize),
      );
    }
  });

  it("hasKey() returns false for empty key", () => {
    const cs = new CipherState(TEST_EMPTY_KEY);
    expect(cs.hasKey()).toStrictEqual(false);
  });

  it("hasKey() returns true for non-empty key", () => {
    const cs = new CipherState(TEST_KEY);
    expect(cs.hasKey()).toStrictEqual(true);
  });

  it("encrypts and decrypts correctly with AAD", () => {
    const cs = new CipherState(TEST_KEY);

    const ciphertext = cs.encrypt(TEST_AD, TEST_PLAINTEXT);
    expect(ciphertext.byteLength).toStrictEqual(
      TEST_PLAINTEXT.byteLength + TAG_SIZE,
    );

    // Decrypt with a new CipherState (to reset nonce)
    const cs2 = new CipherState(TEST_KEY);
    const decrypted = cs2.decrypt(TEST_AD, ciphertext);
    expect(decrypted).toStrictEqual(TEST_PLAINTEXT);
  });

  it("throws if state is wrong", () => {
    const cs = new CipherState(TEST_KEY);
    cs.encrypt(TEST_AD, TEST_PLAINTEXT);

    // Use the same state so the nonce is wrong
    expect(() =>
      cs.decrypt(TEST_AD, cs.encrypt(TEST_AD, TEST_PLAINTEXT)),
    ).toThrow();
  });

  it("throws if ciphertext is tampered", () => {
    const cs = new CipherState(TEST_KEY);
    const ciphertext = cs.encrypt(TEST_AD, TEST_PLAINTEXT);

    // Tamper with ciphertext
    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 0xff;

    const cs2 = new CipherState(TEST_KEY);
    expect(() => cs2.decrypt(TEST_AD, tampered)).toThrow();
  });

  it("throws if tag is tampered", () => {
    const cs = new CipherState(TEST_KEY);
    const ciphertext = cs.encrypt(TEST_AD, TEST_PLAINTEXT);

    // Tamper with tag (last TAG_SIZE bytes)
    const tampered = Buffer.from(ciphertext);
    tampered[tampered.length - 1] ^= 0xff;

    const cs2 = new CipherState(TEST_KEY);
    expect(() => cs2.decrypt(TEST_AD, tampered)).toThrow();
  });
});
