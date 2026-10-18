import { afterEach, describe, expect, it, vi } from "vitest";

class MockNotification {
  static permission: NotificationPermission = "default";
  static requestPermission = vi.fn();

  constructor(
    public title: string,
    public options?: NotificationOptions,
  ) {}
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("requestNotificationPermission", () => {
  it("resolves to unsupported and does not throw when window.Notification is absent", async () => {
    vi.stubGlobal("Notification", undefined);
    const { requestNotificationPermission } = await import("./useNotifications");

    await expect(requestNotificationPermission()).resolves.toBe("unsupported");
  });

  it("resolves to granted without prompting when permission is already granted", async () => {
    MockNotification.permission = "granted";
    MockNotification.requestPermission = vi.fn();
    vi.stubGlobal("Notification", MockNotification);
    const { requestNotificationPermission } = await import("./useNotifications");

    await expect(requestNotificationPermission()).resolves.toBe("granted");
    expect(MockNotification.requestPermission).not.toHaveBeenCalled();
  });

  it("resolves to granted when the user accepts the prompt", async () => {
    MockNotification.permission = "default";
    MockNotification.requestPermission = vi.fn().mockResolvedValue("granted");
    vi.stubGlobal("Notification", MockNotification);
    const { requestNotificationPermission } = await import("./useNotifications");

    await expect(requestNotificationPermission()).resolves.toBe("granted");
    expect(MockNotification.requestPermission).toHaveBeenCalledOnce();
  });

  it("resolves to denied when the user rejects the prompt", async () => {
    MockNotification.permission = "default";
    MockNotification.requestPermission = vi.fn().mockResolvedValue("denied");
    vi.stubGlobal("Notification", MockNotification);
    const { requestNotificationPermission } = await import("./useNotifications");

    await expect(requestNotificationPermission()).resolves.toBe("denied");
  });

  it("supports the legacy callback-style requestPermission API", async () => {
    MockNotification.permission = "default";
    MockNotification.requestPermission = vi.fn((callback?: (permission: NotificationPermission) => void) => {
      callback?.("granted");
      // Legacy implementations return undefined rather than a Promise.
      return undefined as unknown as Promise<NotificationPermission>;
    });
    vi.stubGlobal("Notification", MockNotification);
    const { requestNotificationPermission } = await import("./useNotifications");

    await expect(requestNotificationPermission()).resolves.toBe("granted");
  });
});

describe("showBrowserNotification", () => {
  it("does not throw when window.Notification is absent", async () => {
    vi.stubGlobal("Notification", undefined);
    const { showBrowserNotification } = await import("./useNotifications");

    expect(() => showBrowserNotification("title", "body")).not.toThrow();
  });

  it("constructs a Notification with the given title and body when permission is granted", async () => {
    MockNotification.permission = "granted";
    vi.stubGlobal("Notification", MockNotification);
    const constructorSpy = vi.fn();

    class SpiedNotification extends MockNotification {
      constructor(title: string, options?: NotificationOptions) {
        super(title, options);
        constructorSpy(title, options);
      }
    }
    vi.stubGlobal("Notification", SpiedNotification);

    const { showBrowserNotification } = await import("./useNotifications");
    showBrowserNotification("Agent finished", "Run on project X completed");

    expect(constructorSpy).toHaveBeenCalledWith("Agent finished", { body: "Run on project X completed" });
  });

  it("does not construct a Notification when permission has been revoked since being granted", async () => {
    MockNotification.permission = "granted";
    vi.stubGlobal("Notification", MockNotification);
    const constructorSpy = vi.fn();

    class SpiedNotification extends MockNotification {
      constructor(title: string, options?: NotificationOptions) {
        super(title, options);
        constructorSpy(title, options);
      }
    }
    vi.stubGlobal("Notification", SpiedNotification);

    // Simulate the OS/browser revoking permission after it was granted in-app.
    SpiedNotification.permission = "denied";

    const { showBrowserNotification } = await import("./useNotifications");
    expect(() => showBrowserNotification("title", "body")).not.toThrow();
    expect(constructorSpy).not.toHaveBeenCalled();
  });
});
