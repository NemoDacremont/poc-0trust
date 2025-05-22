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

describe("IKpsk1 Message B", () => {
  let aliceHS: HandshakeInitiator;
  let bobHS: HandshakeResponder;

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

  function doHandshakeA() {
    const payload = Buffer.alloc(0);
    const msgA = aliceHS.writeMessageA(payload).pack();
    // must succeed
    bobHS.readMessageA(msgA, getPSKbyID);
  }

  // Attacker could not reproduce this!
  // function cloneHandshakeState(
  //   hs: HandshakeInitiator | HandshakeResponder
  // ): HandshakeInitiator | HandshakeResponder {
  //   return Object.assign(
  //     Object.create(Object.getPrototypeOf(hs)),
  //     hs
  //   );
  // }

  beforeEach(() => {
    aliceHS = new HandshakeInitiator(hsInitiatorOptions);
    bobHS = new HandshakeResponder(hsResponderOptions);
    doHandshakeA();
  });

  test("Mutual authentication and message integrity", () => {
    const payload = Buffer.from("hello from Bob");
    const msgB = bobHS.writeMessageB(payload).pack();
    const plaintext = aliceHS.readMessageB(msgB);

    expect(plaintext).toStrictEqual(payload);
  });

  test("Sender authentication and KCI resistance (no PSK leak)", () => {
    // simulate compromise of Bob's static only (no PSK leak)
    const oscarHS = new HandshakeResponder({ ...hsResponderOptions });

    // Initialize a symmetric state to writeMessageB
    const fpsk = randomBytes(KEY_SIZE);
    const oscarFriendHS = new HandshakeInitiator({
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
      rs: hsInitiatorOptions.rs, // Bob pub key
      psk: fpsk,
    });
    const fakeMsg = oscarFriendHS.writeMessageA(Buffer.alloc(0)).pack();
    oscarHS.readMessageA(fakeMsg, (_: Key) => fpsk);

    // SymmetricState leak (unlikely)
    // const oscarHS = cloneHandshakeState(bobHS) as HandshakeResponder;
    // expect(bobHS).toStrictEqual(oscarHS);
    // (oscarHS as any).psk = randomBytes(KEY_SIZE);

    const msgB = oscarHS.writeMessageB(Buffer.from("x")).pack();

    expect(() => {
      aliceHS.readMessageB(msgB);
    }).toThrow();
  });

  test("Sender authentication (PSK leak)", () => {
    // simulate compromise of PSK
    const staticKeyOscar = KeyPair.fromPrivate(randomBytes(KEY_SIZE));
    const oscarHS = new HandshakeResponder({
      s: staticKeyOscar,
    });
    (oscarHS as any).psk = (bobHS as any).psk;
    // expect((oscarHS as any).psk).toStrictEqual(
    //   Buffer.from(
    //     "9775b0f777581be4c9922c7b001ec9ce01f044216b4a30d63b5a5b411300c68b",
    //     'hex'
    //   )
    // );

    // Initialize a symmetric state to writeMessageB
    const oscarFriendHS = new HandshakeInitiator({
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
      rs: staticKeyOscar.getPublic(),
      psk: (oscarHS as any).psk,
    });
    const fakeMsg = oscarFriendHS.writeMessageA(Buffer.alloc(0)).pack();
    oscarHS.readMessageA(fakeMsg, (_: Key) => (oscarHS as any).psk);

    const msgB = oscarHS.writeMessageB(Buffer.from("x")).pack();

    expect(() => {
      aliceHS.readMessageB(msgB);
    }).toThrow();
  });

  test("Message secrecy (without keys)", () => {
    const payload = Buffer.from("secret");

    const msgB = bobHS.writeMessageB(payload).pack();

    // Initiator with wrong static *and* wrong PSK
    const oscarHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
      psk: randomBytes(KEY_SIZE),
    });

    expect(() => {
      oscarHS.readMessageB(msgB);
    }).toThrow();
  });

  test("Message secrecy (PSK key leakage)", () => {
    const payload = Buffer.from("secret");

    const msgB = bobHS.writeMessageB(payload).pack();

    // correct static but wrong PSK
    const oscarHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      psk: randomBytes(KEY_SIZE),
    });

    expect(() => {
      oscarHS.readMessageB(msgB);
    }).toThrow();
  });

  test("Message secrecy (Static key leakage)", () => {
    const payload = Buffer.from("secret");

    const msgB = bobHS.writeMessageB(payload).pack();

    // wrong initiator static but correct PSK
    const oscarHS = new HandshakeInitiator({
      ...hsInitiatorOptions,
      s: KeyPair.fromPrivate(randomBytes(KEY_SIZE)),
    });

    expect(() => {
      oscarHS.readMessageB(msgB);
    }).toThrow();
  });
});
