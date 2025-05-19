import { KEY_SIZE, NV_SIZE } from "./constants";

export class SPA {
  static MIN_SIZE = KEY_SIZE + NV_SIZE;

  private e: Buffer;
  private nv: Buffer;
  private nm: Buffer;
  private packet: Buffer;

  constructor(e: Buffer, nv: Buffer, nm: Buffer) {
    this.e = e;
    this.nv = nv;
    this.nm = nm;
    this.packet = Buffer.concat([this.e, this.nv, this.nm]);
  }

  pack() {
    return this.packet;
  }
}
