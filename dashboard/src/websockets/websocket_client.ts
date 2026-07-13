import type { InboundTraffic, OutboundTraffic } from "@/api";

type tCallback = (
  project_id: string,
  message: OutboundTraffic,
) => void | Promise<void>;

class WebSocketClient {
  private static instance: WebSocketClient | null = null;

  active_sockets: { [project_id: string]: WebSocket };
  hooks: {
    [project_id: string]: {
      type: OutboundTraffic["type"];
      callback: tCallback;
    }[];
  };

  readonly baseUrl: string = "/ws";

  constructor() {
    this.active_sockets = {};
    this.hooks = {};
  }

  public static getInstance(): WebSocketClient {
    if (!WebSocketClient.instance) {
      WebSocketClient.instance = new WebSocketClient();
    }

    return WebSocketClient.instance;
  }

  add_hook(
    project_id: string,
    type: OutboundTraffic["type"],
    callback: tCallback,
  ) {
    if (this.hooks[project_id] === undefined) this.hooks[project_id] = [];
    this.hooks[project_id].push({ type: type, callback: callback });
  }

  private add_listener(project_id: string, socket: WebSocket) {
    socket.onmessage = (event: MessageEvent) => {
      try {
        const rawMessage = JSON.parse(event.data);

        if (!rawMessage || typeof rawMessage.type !== "string") {
          console.warn("Received malformed message: ", rawMessage);
          return;
        }

        const message = rawMessage as OutboundTraffic;

        const handlers = this.hooks[project_id]?.filter(
          (hook) => hook.type === message.type,
        );

        if (handlers) {
          handlers.forEach(async (hook) => {
            await hook.callback(project_id, message);
          });
        }
      } catch (error) {
        console.error("Failed to parse incoming message: ", error);
      }
    };
  }

  async connect(project_id: string): Promise<WebSocket> {
    const socketUrl = `${this.baseUrl}/${project_id}`;
    const socket = new WebSocket(socketUrl);

    // Wrap the connection logic in a Promise
    return new Promise((resolve, reject) => {
      const handleOpen = () => {
        cleanup();

        this.active_sockets[project_id] = socket;
        this.add_listener(project_id, socket);

        resolve(socket);
      };

      const handleError = (error: Event) => {
        cleanup();
        reject(error);
      };

      // Helper to remove listeners once one of them fires
      const cleanup = () => {
        socket.removeEventListener("open", handleOpen);
        socket.removeEventListener("error", handleError);
      };

      socket.addEventListener("open", handleOpen);
      socket.addEventListener("error", handleError);
    });
  }

  send_message(project_id: string, message: InboundTraffic) {
    const socket = this.active_sockets[project_id];

    // Check if socket exists
    if (socket === undefined) {
      throw Error("Trying to send message when socket is not created");
    }

    // Check if socket is ready
    if (socket.readyState !== WebSocket.OPEN) {
      throw Error(
        `Cannot send message. Socket state is ${socket.readyState} (not OPEN)`,
      );
    }

    socket.send(JSON.stringify(message));
  }
}

export function useWebSocketClient() {
  return WebSocketClient.getInstance();
}
