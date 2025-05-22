import {
  HandshakeInitiator,
  HandshakeInitiatorOptions,
} from "../src/noise-spa/HandshakeInitiator";
import {
  HandshakeResponder,
  HandshakeResponderOptions,
} from "../src/noise-spa/HandshakeResponder";
import { KeyPair, Key } from "../src";
import { randomBytes } from "crypto";
import { KEY_SIZE } from "../src/noise-spa/constants";

describe("IKpsk1 Message A", () => {
  let aliceHS: HandshakeInitiator;
  let bobHS: HandshakeResponder;

  // Handshake Initatior
  const hsInitiatorOptions: HandshakeInitiatorOptions = {
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

  // Handshake Responder
  const hsResponderOptions: HandshakeResponderOptions = {
    s: KeyPair.fromPrivate(
      Buffer.from(
        "126e5c21772c68e1398cc48c0880f349fb410cdcca953c89a84cdba17fd9df72",
        "hex",
      ),
    ),
  };

  const clients: Record<string, Key> = {
    e51eaac8fe8aac9d95b3a7d215b330fb1b09bafc54625c22e76656190d98b246:
      Buffer.from(
        "9775b0f777581be4c9922c7b001ec9ce01f044216b4a30d63b5a5b411300c68b",
        "hex",
      ),
  };
  const getPSKbyID = (id: Key): Key | null =>
    clients[id.toString("hex")] ?? null;

  beforeEach(() => {
    aliceHS = new HandshakeInitiator(hsInitiatorOptions);
    bobHS = new HandshakeResponder(hsResponderOptions);
  });

  test("Mutual authentification and message integrity", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();
    const { plaintext } = bobHS.readMessageA(msg, getPSKbyID);

    expect(plaintext).toStrictEqual(payload);
  });

  test("Sender authentication and KCI resistance (no PSK leak)", () => {
    // simulate compromise of Alice's static only (no PSK leak)
    const oscarHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      psk: randomBytes(KEY_SIZE),
    });

    const msg = oscarHS.writeMessageA(Buffer.from("x")).pack();

    // should NOT accept a message if only Alice's static key was compromised
    expect(() => {
      bobHS.readMessageA(msg, getPSKbyID);
    }).toThrow();
  });

  test("Sender authentification (PSK leak)", () => {
    // simulate compromise of PSK
    const oscarHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });

    const payload = Buffer.from("x");
    const msg = oscarHS.writeMessageA(payload).pack();

    // should NOT accept the message if only the PSK leaked
    expect(() => {
      bobHS.readMessageA(msg, getPSKbyID);
    }).toThrow();
  });

  test("Sender authentification (PSK leak + Alice pub key)", () => {
    // simulate compromise of PSK + Alice pub key
    const oscarHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      s: new KeyPair(
        Buffer.from(
          "e51eaac8fe8aac9d95b3a7d215b330fb1b09bafc54625c22e76656190d98b246",
          "hex",
        ),
        randomBytes(KEY_SIZE),
      ),
    });

    const payload = Buffer.from("x");
    const msg = oscarHS.writeMessageA(payload).pack();

    // should NOT accept the message if the PSK leaked
    // and Oscar include the Alice public key
    expect(() => {
      bobHS.readMessageA(msg, getPSKbyID);
    }).toThrow();
  });

  test("Message secrecy (without keys)", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();

    // Attacker has no keys
    const oscarHS = new HandshakeResponder({
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });
    const getFakePSK = (rs: Key): Buffer => randomBytes(KEY_SIZE);

    // should not read the message from Alice
    expect(() => {
      oscarHS.readMessageA(msg, getFakePSK);
    }).toThrow();
  });

  test("Message secrecy (PSK key leakage)", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();

    // PSK Key leakage
    const oscarHS = new HandshakeResponder({
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });

    expect(() => {
      oscarHS.readMessageA(msg, getPSKbyID);
    }).toThrow();
  });

  test("Message secrecy (Static keys leakage)", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();

    // Bob's static keys leakage
    const oscarHS = new HandshakeResponder(hsResponderOptions);
    const getFakePSK = (rs: Key): Buffer => randomBytes(KEY_SIZE);

    expect(() => {
      oscarHS.readMessageA(msg, getFakePSK);
    }).toThrow();
  });
});
