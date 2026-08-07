import type { InboundTraffic, OutboundTraffic } from "@/api";

export type tCallback = (message: OutboundTraffic) => void | Promise<void>;

class WebSocketClient {
  private static instance: WebSocketClient | null = null;

  active_socket: WebSocket | undefined;
  hooks: {
    [K in OutboundTraffic["type"]]?: tCallback[];
  };

  readonly baseUrl: string = "/ws/client";

  constructor() {
    this.hooks = {};
  }

  public static getInstance(): WebSocketClient {
    if (!WebSocketClient.instance) {
      WebSocketClient.instance = new WebSocketClient();
      WebSocketClient.instance.connect().catch((e) => console.error(e));
    }

    return WebSocketClient.instance;
  }

  hook_exists(type: OutboundTraffic["type"], callback: tCallback) {
    const hookExists = this.hooks[type]?.some((cb) => cb === callback);

    return hookExists;
  }

  add_hook(type: OutboundTraffic["type"], callback: tCallback) {
    if (this.hooks[type] === undefined) {
      this.hooks[type] = [];
    }

    if (this.hook_exists(type, callback)) {
      // Log a warning or just return early silently
      console.warn(`Duplicate hook detected for type "${type}". Ignoring.`);
      return;
    }

    this.hooks[type].push(callback);

    return { delete: () => this.remove_hook(type, callback) };
  }

  remove_hook(type: OutboundTraffic["type"], callback: tCallback) {
    if (!this.hooks[type]) return;

    this.hooks[type] = this.hooks[type]!.filter((cb) => cb !== callback);
  }

  private add_listener(socket: WebSocket) {
    socket.onmessage = (event: MessageEvent) => {
      try {
        const rawMessage = JSON.parse(event.data);

        if (!rawMessage || typeof rawMessage.type !== "string") {
          console.warn("Received malformed message: ", rawMessage);
          return;
        }

        const message = rawMessage as OutboundTraffic;

        const handlers = this.hooks[message.type];

        if (handlers) {
          handlers.forEach(async (callback) => {
            await callback(message);
          });
        }
      } catch (error) {
        console.error("Failed to parse incoming message: ", error);
      }
    };
  }

  private async connect(): Promise<WebSocket> {
    const socketUrl = `${this.baseUrl}`;
    const socket = new WebSocket(socketUrl);

    // Wrap the connection logic in a Promise
    return new Promise((resolve, reject) => {
      const handleOpen = () => {
        cleanup();

        this.active_socket = socket;
        this.add_listener(socket);

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
  // Inbound traffic -> to backend
  send_message(message: InboundTraffic) {
    const socket = this.active_socket;

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

  isSocketActive() {
    return this.active_socket?.readyState === WebSocket.OPEN;
  }
}

export function useWebSocketClient() {
  return WebSocketClient.getInstance();
}
