/* Service Worker for Web Push Notifications */

self.addEventListener('push', function(event) {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = {};
  }

  const title = data.title || 'Update';
  const options = {
    body: data.body || 'Open the site for the latest updates.',
    data: {
      url: data.url || '/',
    },
    // You can add icon/badge later if you want:
    // icon: '/static/img/icon-192.png',
    // badge: '/static/img/badge-72.png',
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
  event.notification.close();
  const url = (event.notification && event.notification.data && event.notification.data.url) ? event.notification.data.url : '/';

  event.waitUntil((async () => {
    const allClients = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of allClients) {
      if ('focus' in client) {
        // If already open, focus it and navigate.
        try { client.navigate(url); } catch (e) {}
        return client.focus();
      }
    }
    if (clients.openWindow) {
      return clients.openWindow(url);
    }
  })());
});
