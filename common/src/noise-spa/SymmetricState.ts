import { createHash, hkdfSync } from "crypto";
import { KEY_SIZE } from "./constants"
import { CipherState } from "./CipherState";

export type ProtocolNameType = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s" | "not implemented";
export type HashNameType = "BLAKE2s256";


export class SymmetricState {
    private h: Buffer
    private ck: Buffer
    private cs: CipherState
    private hashName: HashNameType;

    constructor(protocolName: ProtocolNameType, hashName: HashNameType) {
        const name = Buffer.from(protocolName, 'utf-8')
        const protocolNamePadded = Buffer.alloc(Math.max(32, name.length))
        name.copy(protocolNamePadded)

        this.hashName = hashName;

        this.h = this.hash(protocolNamePadded)
        this.ck = this.h.subarray()
        this.cs = new CipherState(Buffer.alloc(KEY_SIZE))
    }

    private hash(...inputs: Buffer[]): Buffer {
        const hasher = createHash(this.hashName)

        for (const input of inputs)
            hasher.update(input)

        return hasher.digest()
    }

    private hkdf(ikm: Buffer, salt: Buffer, size: number) {
        return Buffer.from(hkdfSync(this.hashName, ikm, salt, Buffer.alloc(0), size))
    }


    mixHash(data: Buffer) {
        this.h = this.hash(this.h, data)
    }

    mixKey(ikm: Buffer) {
        const derived = this.hkdf(ikm, this.ck, KEY_SIZE * 2)

        this.ck = derived.subarray(0, KEY_SIZE)
        const newKey = derived.subarray(KEY_SIZE, KEY_SIZE * 2)

        this.cs = new CipherState(newKey)
    }

    mixKeyAndHash(ikm: Buffer) {
        const derived = this.hkdf(ikm, this.ck, KEY_SIZE * 3)
        this.ck = derived.subarray(0, KEY_SIZE)

        const hash = derived.subarray(KEY_SIZE * 1, KEY_SIZE * 2)
        const key = derived.subarray(KEY_SIZE * 2, KEY_SIZE * 3)

        this.mixHash(hash)
        this.cs = new CipherState(key)
    }

    encryptAndHash(plaintext: Buffer): Buffer {
        const ciphertext = this.cs.hasKey() ? this.cs.encrypt(this.h, plaintext) : plaintext;
        this.mixHash(ciphertext);

        return ciphertext;
    }

    decryptAndHash(ciphertext: Buffer): Buffer {
        const plaintext = this.cs.hasKey() ? this.cs.decrypt(this.h, ciphertext) : ciphertext;
        this.mixHash(ciphertext);

        return plaintext;
    }
}
