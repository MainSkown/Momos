/// <reference types="node" />
import { afterEach, describe, expect, it, vi } from "vitest";

class MockWebSocket {
  static OPEN = 1;
  static CONNECTING = 0;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  readyState = MockWebSocket.CONNECTING;
  onmessage: ((event: { data: string }) => void) | null = null;
  send = vi.fn();

  private listeners: Record<string, Array<(event?: unknown) => void>> = {};

  constructor(public url: string) {
    MockWebSocket.instances.push(this);
  }

  addEventListener(type: string, cb: (event?: unknown) => void) {
    (this.listeners[type] ??= []).push(cb);
  }

  removeEventListener(type: string, cb: (event?: unknown) => void) {
    this.listeners[type] = (this.listeners[type] ?? []).filter((c) => c !== cb);
  }

  dispatch(type: string, event?: unknown) {
    (this.listeners[type] ?? []).forEach((cb) => cb(event));
  }
}

async function freshOpenClient() {
  vi.resetModules();
  MockWebSocket.instances = [];
  vi.stubGlobal("WebSocket", MockWebSocket);

  const { useWebSocketClient } = await import("@/websockets/websocket_client");
  const client = useWebSocketClient();
  const socket = MockWebSocket.instances[0]!;
  socket.dispatch("open");

  return { client, socket };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("websocket_client reconnect behavior", () => {
  it("does not replace active_socket or reconnect when the socket later closes (confirmed gap: no onclose/onerror handler)", async () => {
    const { client, socket } = await freshOpenClient();

    expect(client.active_socket).toBe(socket);

    socket.readyState = MockWebSocket.CLOSED;
    socket.dispatch("close");

    expect(MockWebSocket.instances).toHaveLength(1);
    expect(client.active_socket).toBe(socket);
    expect(client.active_socket?.readyState).toBe(MockWebSocket.CLOSED);
  });
});

describe("websocket_client hook dispatch error handling", () => {
  it("a hook that throws during the async dispatch loop escapes as an unhandled rejection rather than being caught/logged (confirmed bug)", async () => {
    const { client, socket } = await freshOpenClient();

    const rejections: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => rejections.push(reason);
    process.on("unhandledRejection", onUnhandledRejection);

    try {
      client.add_hook("AgentRunTimer", async () => {
        throw new Error("hook boom");
      });

      socket.onmessage!({ data: JSON.stringify({ type: "AgentRunTimer" }) });

      await new Promise((resolve) => setTimeout(resolve, 0));
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(rejections).toHaveLength(1);
      expect((rejections[0] as Error).message).toBe("hook boom");
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
    }
  });
});
