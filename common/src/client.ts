export class Client {
    constructor() {
    }

    async send(message: Buffer): Promise<Buffer> {
        return new Promise((res, _) => {
            res(Buffer.alloc(0));
        });
    }
}
