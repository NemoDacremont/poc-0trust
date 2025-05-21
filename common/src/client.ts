import { createSocket } from "dgram";
import {
  HandshakeInitiator,
  HandshakeInitiatorOptions,
} from "./noise-spa/HandshakeInitiator";
import { KeyPair } from "./noise-spa/KeyPair";
import { Key } from "./noise-spa/utils";

export class Client {
  private host;
  private port;
  private s: KeyPair;
  private rs: Key;
  private psk: Key;

  constructor(
    host: string,
    port: number,
    hsOptions: HandshakeInitiatorOptions,
  ) {
    this.host = host;
    this.port = port;
    this.s = hsOptions.s;
    this.rs = hsOptions.rs;
    this.psk = hsOptions.psk;
  }

  async send(message: Buffer): Promise<Buffer> {
    const socket = createSocket("udp4");

    const hs = new HandshakeInitiator({
      s: this.s,
      rs: this.rs,
      psk: this.psk,
    });
    const spaMessage = hs.writeMessageA(message).pack();

    return new Promise((res, rej) => {
      socket.on("message", (message, _rinfo) => {
        const plaintext = hs.readMessageB(message);

        res(plaintext);
        socket.close();
      });

      socket.send(spaMessage, this.port, this.host, (err) => {
        if (err) rej(err);
      });
    });
  }
}
