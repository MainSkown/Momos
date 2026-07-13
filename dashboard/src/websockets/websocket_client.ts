import type { InboundTraffic } from "@/api"


class WebSocketClient{
    private static instance: WebSocketClient | null = null

    active_sockets: {[project_id: string] : WebSocket}
    readonly baseUrl: string = '/ws'

    constructor() {
        this.active_sockets = {}
    }

    public static getInstance(): WebSocketClient {
        if (!WebSocketClient.instance){
            WebSocketClient.instance = new WebSocketClient()
        }

        return WebSocketClient.instance
    }

    async connect(project_id: string): Promise<WebSocket> {
    const socketUrl = `${this.baseUrl}/${project_id}`;
    const socket = new WebSocket(socketUrl);        

    // Wrap the connection logic in a Promise
    return new Promise((resolve, reject) => {        
        const handleOpen = () => {
            cleanup();

            this.active_sockets[project_id] = socket;
            resolve(socket);
        };

        const handleError = (error: Event) => {
            cleanup();
            reject(error);
        };

        // Helper to remove listeners once one of them fires
        const cleanup = () => {
            socket.removeEventListener('open', handleOpen);
            socket.removeEventListener('error', handleError);
        };

        socket.addEventListener('open', handleOpen);
        socket.addEventListener('error', handleError);
    });
}

    send_message(project_id: string, message: InboundTraffic){
        const socket = this.active_sockets[project_id]

        // Check if socket exists
        if(socket === undefined){
            throw Error("Trying to send message when socket is not created")
        }

        // Check if socket is ready
        if (socket.readyState !== WebSocket.OPEN) {
            throw Error(`Cannot send message. Socket state is ${socket.readyState} (not OPEN)`)
        }

        socket.send(JSON.stringify(message))
    }
}

export function useWebSocketClient(){
    return WebSocketClient.getInstance()
}