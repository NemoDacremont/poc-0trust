import { createInterface } from "readline/promises";
import { Client } from "../../common/src/client";
import { HandshakeInitiatorOptions } from "../../common/src/noise-spa/HandshakeInitiator";
import { KeyPair } from "../../common/src";

const rl = createInterface({
  input: process.stdin,
  output: process.stdout,
});

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

const client = new Client("localhost", 12345, hsOptions);

(async () => {
  const message = await rl.question("");
  const data = Buffer.from(message);

  console.log(`Sent : ${data}`);
  const response = await client.send(data);
  console.log(`Received : ${response}`);
})();
