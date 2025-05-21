import { randomBytes, randomInt } from "crypto";
import { KEY_SIZE, NV_SIZE } from "../src/noise-spa/constants";
import { SPA } from "../src/noise-spa/SPA";

const e = Buffer.from(
  "deadbeefcafe0123456789deadbeefcafe0123456789deadbeefcafe01234567",
  "hex",
);
const nv = Buffer.from(
  "cafe0123beefdead4567cafe0123beefdead4567cafe0123beefdead4567cafe0123beefdead4567cafe0123beefdead4567cafe0123beef",
  "hex",
);
const nm = Buffer.from(
  "376831735f31355f346e5f4e635259703733445f6d3335733467335f286e6f29",
  "hex",
);

// concatenation of e, nv and nm
const message2unpack = Buffer.from(
  "deadbeefcafe0123456789deadbeefcafe0123456789deadbeefcafe01234567cafe0123beefdead4567cafe0123beefdead4567cafe0123beefdead4567cafe0123beefdead4567cafe0123beefdead4567cafe0123beef376831735f31355f346e5f4e635259703733445f6d3335733467335f286e6f29",
  "hex",
);

// This makes the max message length to be 4096
const MAX_RANDNM_LENGTH = 4096 - NV_SIZE - KEY_SIZE;

describe("SPA unit tests", () => {
  it("should return the right ephemeral key", () => {
    const spa = new SPA(e, nv, nm);

    expect(spa.getKey()).toStrictEqual(e);

    // Random tests
    for (let i = 0; i < 20; ++i) {
      const randomE = randomBytes(KEY_SIZE);

      const randomSPA = new SPA(randomE, nv, nm);
      expect(randomSPA.getKey()).toStrictEqual(randomE);
    }
  });

  it("should return the right nv", () => {
    const spa = new SPA(e, nv, nm);

    expect(spa.getValue()).toStrictEqual(nv);

    // Random tests
    for (let i = 0; i < 20; ++i) {
      const randomNV = randomBytes(NV_SIZE);

      const randomSPA = new SPA(e, randomNV, nm);
      expect(randomSPA.getValue()).toStrictEqual(randomNV);
    }
  });

  it("should return the right ciphertext", () => {
    const spa = new SPA(e, nv, nm);

    expect(spa.getCiphertext()).toStrictEqual(nm);

    // Random tests
    for (let i = 0; i < 20; ++i) {
      const randomNM = randomBytes(randomInt(MAX_RANDNM_LENGTH));

      const randomSPA = new SPA(e, nv, randomNM);
      expect(randomSPA.getCiphertext()).toStrictEqual(randomNM);
    }
  });

  it("should create the right SPA buffer", () => {
    const spa = new SPA(e, nv, nm);

    expect(spa.pack()).toStrictEqual(Buffer.concat([e, nv, nm]));

    // Random tests
    for (let i = 0; i < 20; ++i) {
      const randomE = randomBytes(KEY_SIZE);
      const randomNV = randomBytes(NV_SIZE);
      const randomNM = randomBytes(randomInt(MAX_RANDNM_LENGTH));

      const randomSPA = new SPA(randomE, randomNV, randomNM);
      const expected = Buffer.concat([randomE, randomNV, randomNM]);
      expect(randomSPA.pack()).toStrictEqual(expected);
    }
  });

  it("should unpack the message into the right SPA object", () => {
    const spa = SPA.unpack(message2unpack);

    expect(spa.getKey()).toStrictEqual(e);
    expect(spa.getValue()).toStrictEqual(nv);
    expect(spa.getCiphertext()).toStrictEqual(nm);

    // Random tests
    for (let i = 0; i < 20; ++i) {
      const mini = KEY_SIZE + NV_SIZE;
      const randomMessage = randomBytes(
        randomInt(mini, mini + MAX_RANDNM_LENGTH),
      );

      const randomSpa = SPA.unpack(randomMessage);
      const randomE = randomMessage.subarray(0, KEY_SIZE);
      const randomNV = randomMessage.subarray(KEY_SIZE, KEY_SIZE + NV_SIZE);
      const randomNM = randomMessage.subarray(KEY_SIZE + NV_SIZE);

      expect(randomSpa.getKey()).toStrictEqual(randomE);
      expect(randomSpa.getValue()).toStrictEqual(randomNV);
      expect(randomSpa.getCiphertext()).toStrictEqual(randomNM);
    }
  });

  it("should throw an error if data is too small", () => {
    for (let i = 0; i < SPA.MIN_SIZE; ++i) {
      const smallBuffer = randomBytes(SPA.MIN_SIZE - i - 1);
      expect(() => SPA.unpack(smallBuffer)).toThrow("Data too small");
    }
  });
});
