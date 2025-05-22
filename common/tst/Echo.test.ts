import {
  Key,
  KeyPair,
  Client,
  Server,
  HandshakeInitiatorOptions,
} from "../src";

describe("UDP Echo Server", () => {
  // UDP Parameters
  const HOST = "127.0.0.1";
  const PORT = 41234;

  let server: Server;
  let client: Client;

  // Server-specific parameters
  const s = KeyPair.fromPrivate(
    Buffer.from(
      "126e5c21772c68e1398cc48c0880f349fb410cdcca953c89a84cdba17fd9df72",
      "hex",
    ),
  );

  const clients: Record<string, Key> = {
    e51eaac8fe8aac9d95b3a7d215b330fb1b09bafc54625c22e76656190d98b246:
      Buffer.from(
        "9775b0f777581be4c9922c7b001ec9ce01f044216b4a30d63b5a5b411300c68b",
        "hex",
      ),
  };
  const getPSKbyID = (id: Key): Key | null =>
    clients[id.toString("hex")] ?? null;

  // Client-specific parameters
  const hsOptions: HandshakeInitiatorOptions = {
    s: KeyPair.fromPrivate(
      Buffer.from(
        "5db979a88bc2a2203df03acf4dd946b89fdb9293242a557778c69b7f29382e76",
        "hex",
      ),
    ),
    rs: Buffer.from(
      "d922a623f61caadbd44f716dcd9f59423c791f50e016eb9cfed28509b334f80b",
      "hex",
    ),
    psk: Buffer.from(
      "9775b0f777581be4c9922c7b001ec9ce01f044216b4a30d63b5a5b411300c68b",
      "hex",
    ),
  };

  beforeAll((done) => {
    server = new Server(HOST, PORT, s, getPSKbyID);
    server.bind();

    server.on("listening", () => {
      server.on("message", (msg, { send }) => {
        send(msg.toString());
      });
      done();
    });
  });

  afterAll((done) => {
    server.once("close", done);
    server["socket"].close();
  });

  it("should echo back the same message", async () => {
    client = new Client(HOST, PORT, hsOptions);
    const payload = Buffer.from("hello, world");
    const response = await client.send(payload);
    expect(response.toString()).toBe("hello, world");
  });

  it("should handle multiple messages", async () => {
    client = new Client(HOST, PORT, hsOptions);
    for (const text of ["foo", "bar", "baz"]) {
      const buf = Buffer.from(text);
      const res = await client.send(buf);
      expect(res.toString()).toBe(text);
    }
  });
});
