import { createInterface } from "readline/promises";
import { Client } from "../../common/src/client";

const rl = createInterface({
  input: process.stdin,
  output: process.stdout,
});

const client = new Client("localhost", 12345);

(async () => {
  const message = await rl.question("");
  const data = Buffer.from(message);

  console.log(`Sent : ${data}`);
  const response = await client.send(data);
  console.log(`Received : ${response}`);
})();
