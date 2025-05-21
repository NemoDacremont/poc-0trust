import { HandshakeInitiatorOptions } from "./noise-spa/HandshakeInitiator";
import { HandshakeResponderOptions } from "./noise-spa/HandshakeResponder";
import { KeyPair } from "./noise-spa/KeyPair";
import type { Key } from "./noise-spa/utils";
import { Client } from "./client";
import { Server } from "./server";

export type { Key, HandshakeInitiatorOptions, HandshakeResponderOptions };

export { KeyPair, Client, Server };
