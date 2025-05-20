import { EventEmitter } from "stream";
import { createSocket, RemoteInfo } from "dgram";
import { HandshakeResponder } from "./noise-spa/HandshakeResponder";
import { KeyPair } from "./noise-spa/KeyPair";

type Response = (message: Buffer) => Promise<void>;

export interface ServerEvents {
  connect: [];
  close: [];
  listening: [];
  error: [Error];
  message: [msg: Buffer, { send: (msg: string) => void }];
}

export class Server extends EventEmitter<ServerEvents> {
  private socket;
  private host;
  private port;
  private s: KeyPair;

  constructor(host: string, port: number, s: KeyPair) {
    super();
    this.socket = createSocket("udp4");
    this.host = host;
    this.port = port;
    this.s = s;

    this.socket.on("connect", () => this.emit("connect"));
    this.socket.on("listening", () => this.emit("listening"));
    this.socket.on("error", (err) => this.emit("error", err));
    this.socket.on("close", () => this.emit("close"));
    this.socket.on("message", this.onMessage);
  }

  private onMessage(data: Buffer, rinfo: RemoteInfo) {
    const client = createSocket("udp4");
    const hs = new HandshakeResponder({ s: this.s });

    const { timestamp, plaintext } = hs.readMessageA(data, () => null);

    // Let the user use plaintext to create msg
    this.emit("message", plaintext, {
      send: (msg: string) => {
        const cipher = hs.writeMessageB(Buffer.from(msg));

        client.send(cipher, rinfo.port, rinfo.address);
      },
    });
  }

  bind() {
    this.socket.bind(this.port, this.host);
  }
}
