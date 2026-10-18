export type NotificationRequestResult = "granted" | "denied" | "unsupported";

function getNotificationCtor(): typeof Notification | undefined {
  return typeof Notification === "undefined" ? undefined : Notification;
}

/**
 * Resolves the browser's current/soon-to-be notification permission, prompting
 * the user only if a decision hasn't already been made. Never throws: an
 * unsupported browser resolves to "unsupported" rather than rejecting.
 */
export async function requestNotificationPermission(): Promise<NotificationRequestResult> {
  const NotificationCtor = getNotificationCtor();
  if (!NotificationCtor) {
    return "unsupported";
  }

  if (NotificationCtor.permission === "granted") {
    return "granted";
  }

  // Safari <16 and other older engines implement requestPermission as a
  // callback API instead of returning a Promise.
  const permission = await new Promise<NotificationPermission>((resolve) => {
    const result = NotificationCtor.requestPermission(resolve);
    if (result && typeof result.then === "function") {
      result.then(resolve);
    }
  });

  return permission === "granted" ? "granted" : "denied";
}

/**
 * Fires a browser notification, re-checking permission live rather than
 * trusting a previously cached "granted" state, since the user may have
 * revoked it at the OS/browser level after granting it in-app. A no-op
 * (never throws) when unsupported or not currently permitted.
 */
export function showBrowserNotification(title: string, body: string): void {
  const NotificationCtor = getNotificationCtor();
  if (!NotificationCtor || NotificationCtor.permission !== "granted") {
    return;
  }

  new NotificationCtor(title, { body });
}

export function useNotifications() {
  return { requestNotificationPermission, showBrowserNotification };
}
