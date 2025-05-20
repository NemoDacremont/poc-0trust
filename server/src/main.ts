import { Server } from "../../common/src/server";

const server = new Server("localhost", 12345);

server.on("message", (msg, client) => {
  console.log(`Received : ${msg}`);
  client.send(msg.toString());
  console.log(`Sent : ${msg}`);
});

server.bind();
