import { Socket} from 'dgram'

type Response = (message: Buffer) => Promise<void>

export class Server extends Socket {

    onMessage(callback: (data: Buffer, res: Response) => void) {}

    bind(host: string, port: number) {}
}
