import { KeyPair } from "../../common/src";
import { Server } from "../../common/src/server";

const s = KeyPair.fromPrivate(
  Buffer.from(
    "126e5c21772c68e1398cc48c0880f349fb410cdcca953c89a84cdba17fd9df72",
    "hex",
  ),
);
const server = new Server("localhost", 12345, s);

server.on("message", (msg, client) => {
  console.log(`Received : ${msg}`);
  client.send(msg.toString());
  console.log(`Sent : ${msg}`);
});

server.bind();
