import { KEY_SIZE, NV_SIZE } from "./constants";

export class SPA {
  static MIN_SIZE = KEY_SIZE + NV_SIZE;

  private e: Buffer;
  private nv: Buffer;
  private nm: Buffer;

  constructor(e: Buffer, nv: Buffer, nm: Buffer) {
    this.e = e;
    this.nv = nv;
    this.nm = nm;
  }

  pack() {
    return Buffer.concat([this.e, this.nv, this.nm]);
  }

  static unpack(data: Buffer) {
    if (data.length < SPA.MIN_SIZE) throw new Error("Data too small");

    return new SPA(
      data.subarray(0, KEY_SIZE),
      data.subarray(KEY_SIZE, KEY_SIZE + NV_SIZE),
      data.subarray(KEY_SIZE + NV_SIZE),
    );
  }

  getKey(): Buffer {
    return this.e;
  }

  getValue(): Buffer {
    // rs + timestamp + ad (tag)
    return this.nv;
  }

  getCiphertext(): Buffer {
    return this.nm;
  }
}
