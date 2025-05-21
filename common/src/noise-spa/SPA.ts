import assert from "assert";
import { KEY_SIZE, NV_SIZE } from "./constants";
import { Key } from "./utils";
import { InvalidKeySizeError } from "./exceptions/InvalidKeySizeError";
import { InvalidNVSizeError } from "./exceptions/InvalidNVSizeError";
import { InvalidDataSizeError } from "./exceptions/InvalidDataSizeError";

export class SPA {
  static MIN_SIZE = KEY_SIZE + NV_SIZE;

  private e: Key; // Public ephemeral key
  private nv: Buffer;
  private nm: Buffer;

  constructor(e: Key, nv: Buffer, nm: Buffer) {
    assert(
      e.byteLength == KEY_SIZE,
      new InvalidKeySizeError(KEY_SIZE, e.byteLength),
    );
    assert(
      nv.byteLength == NV_SIZE,
      new InvalidNVSizeError(NV_SIZE, nv.byteLength),
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
      data.byteLength >= SPA.MIN_SIZE,
      new InvalidDataSizeError(SPA.MIN_SIZE, data.byteLength),
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
