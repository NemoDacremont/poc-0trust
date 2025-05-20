import { Socket} from 'dgram'
import { EventEmitter } from 'stream'
import { createSocket } from 'dgram';
import { Client } from './client';

type Response = (message: Buffer) => Promise<void>

export interface ServerEvents {
        'connect': [];
        'close': [];
        'listening': [];
        'error': [Error];
        'message': [msg: Buffer, {send: (msg: string) => void}];
}

export class Server extends EventEmitter<ServerEvents> {
    private socket;
    private host;
    private port;

    constructor (host: string, port: number) {
        super();
        this.socket = createSocket('udp4');
        this.host = host;
        this.port = port;

        this.socket.on('connect', () => this.emit('connect'));
        this.socket.on('listening', () => this.emit('listening'));
        this.socket.on('error', (err) => this.emit('error', err));
        this.socket.on('close', () => this.emit('close'));

        this.socket.on('message', (msg, rinfo) => {
            const client = createSocket('udp4');

            this.emit('message', msg, {
                send: (msg: string) => {
                    const data = Buffer.from(msg);
                    client.send(data, rinfo.port, rinfo.address)
                },
            });
        });
    }

    bind () {
        this.socket.bind(this.port, this.host);
    }
}
