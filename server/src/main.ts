import { Key, KeyPair, Server } from "../../common/src";

const s = KeyPair.fromPrivate(
  Buffer.from(
    "126e5c21772c68e1398cc48c0880f349fb410cdcca953c89a84cdba17fd9df72",
    "hex",
  ),
);

// Fake function
const clients: Record<string, Key> = {
  e51eaac8fe8aac9d95b3a7d215b330fb1b09bafc54625c22e76656190d98b246: Buffer.from(
    "9775b0f777581be4c9922c7b001ec9ce01f044216b4a30d63b5a5b411300c68b",
    "hex",
  ),
};
const getPSKbyID = (id: Key): Key | null => clients[id.toString("hex")] ?? null;

const server = new Server("localhost", 12345, s, getPSKbyID);

server.on("message", (msg, client) => {
  console.log(`Received : ${msg}`);
  client.send(msg.toString());
  console.log(`Sent : ${msg}`);
});

server.bind();
