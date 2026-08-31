self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch { payload = {}; }
  const title = payload.title === "Whisper" ? payload.title : "Whisper";
  event.waitUntil(self.registration.showNotification(title, {
    body: "New encrypted message",
    tag: "whisper-message",
    renotify: false,
    silent: false,
    data: { url: "/" },
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
    const existing = clients.find((client) => new URL(client.url).origin === self.location.origin);
    return existing ? existing.focus() : self.clients.openWindow("/");
  }));
});
