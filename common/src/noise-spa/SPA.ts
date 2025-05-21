import assert from "assert";
import { KEY_SIZE, NV_SIZE } from "./constants";
import { Key } from "./utils";

export class SPA {
  static MIN_SIZE = KEY_SIZE + NV_SIZE;

  private e: Key; // Public ephemeral key
  private nv: Buffer;
  private nm: Buffer;

  constructor(e: Key, nv: Buffer, nm: Buffer) {
    assert(
      e.length == KEY_SIZE,
      `e should be exactly ${KEY_SIZE} bytes long, got ${e.length} bytes long`,
    );
    assert(
      nv.length == NV_SIZE,
      `nv should be exactly ${NV_SIZE} bytes long, got ${nv.length} bytes long`,
    );

    this.e = e;
    this.nv = nv;
    this.nm = nm;
  }

  pack() {
    return Buffer.concat([this.e, this.nv, this.nm]);
  }

  static unpack(data: Buffer): SPA {
    assert(
      data.length >= SPA.MIN_SIZE,
      `data should be at least ${SPA.MIN_SIZE} bytes long, got ${data.length} bytes long`,
    );

    return new SPA(
      data.subarray(0, KEY_SIZE),
      data.subarray(KEY_SIZE, KEY_SIZE + NV_SIZE),
      data.subarray(KEY_SIZE + NV_SIZE),
    );
  }

  getKey(): Key {
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
