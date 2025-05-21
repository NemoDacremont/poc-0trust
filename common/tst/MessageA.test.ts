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
    const { timestamp, plaintext } = bobHS.readMessageA(msg, getPSKbyID);

    // expect(ok).toBe(true);
    expect(plaintext).toEqual(payload);
  });

  test("Sender authentication and KCI resistance", () => {
    // simulate compromise of Alice's static only (no PSK leak)
    aliceHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });

    const msg = aliceHS.writeMessageA(Buffer.from("x")).pack();

    // should NOT accept a message if only Alice's static key was compromised
    expect(() => {
      bobHS.readMessageA(msg, getPSKbyID);
    }).toThrow(Error);
  });

  test("Message secrecy (without keys)", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();

    // No keys
    bobHS = new HandshakeResponder({
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });
    const getFakePSK = (rs: Key): Buffer => randomBytes(KEY_SIZE);

    expect(() => {
      bobHS.readMessageA(msg, getFakePSK);
    }).toThrow();
  });

  test("Message secrecy (PSK key leakage)", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();

    // PSK Key leakage
    bobHS = new HandshakeResponder({
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });

    expect(() => {
      bobHS.readMessageA(msg, getPSKbyID);
    }).toThrow();
  });

  test("Message secrecy (Static keys leakage)", () => {
    const payload = Buffer.from("hello");
    const msg = aliceHS.writeMessageA(payload).pack();

    // Bob's static keys leakage
    // bobHS = new HandshakeResponder(hsResponderOptions);
    const getFakePSK = (rs: Key): Buffer => randomBytes(KEY_SIZE);

    expect(() => {
      bobHS.readMessageA(msg, getFakePSK);
    }).toThrow();
  });
});
