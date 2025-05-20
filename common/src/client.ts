import { createSocket } from "dgram";

export class Client {
    private host;
    private port;

    constructor(host: string, port: number) {
        this.host = host;
        this.port = port;
    }

    async send(message: Buffer): Promise<Buffer> {
        const socket = createSocket('udp4');

        return new Promise((res, rej) => {
            socket.on("message", (message, _rinfo) => {
                res(message);
                socket.close()
            });

            socket.send(message, this.port, this.host, (err) => {
                if (err)
                    rej(err);
            });
        });
    }
}
