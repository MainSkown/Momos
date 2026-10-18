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
  it("drops active_socket and reconnects with a new socket after the socket closes (fixed)", async () => {
    vi.useFakeTimers();

    try {
      const { client, socket } = await freshOpenClient();

      expect(client.active_socket).toBe(socket);

      socket.readyState = MockWebSocket.CLOSED;
      socket.dispatch("close");

      // The stale socket is dropped immediately...
      expect(client.active_socket).toBeUndefined();

      // ...and a reconnect attempt is scheduled rather than happening inline.
      expect(MockWebSocket.instances).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(5000);

      expect(MockWebSocket.instances).toHaveLength(2);
      const newSocket = MockWebSocket.instances[1]!;
      newSocket.dispatch("open");

      expect(client.active_socket).toBe(newSocket);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("websocket_client hook dispatch error handling", () => {
  it("catches and logs a hook that throws during the async dispatch loop instead of letting it escape as an unhandled rejection (fixed)", async () => {
    const { client, socket } = await freshOpenClient();

    const rejections: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => rejections.push(reason);
    process.on("unhandledRejection", onUnhandledRejection);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      client.add_hook("AgentRunTimer", async () => {
        throw new Error("hook boom");
      });

      socket.onmessage!({ data: JSON.stringify({ type: "AgentRunTimer" }) });

      await new Promise((resolve) => setTimeout(resolve, 0));
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(rejections).toHaveLength(0);
      const loggedHookError = errorSpy.mock.calls.find((args) =>
        args.some((arg) => arg instanceof Error && arg.message === "hook boom"),
      );
      expect(loggedHookError).toBeDefined();
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
      errorSpy.mockRestore();
    }
  });
});
