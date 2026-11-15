self.addEventListener('push', function (event) {
    let payload = {
        title: 'System Ministranci',
        body: 'Masz nowe powiadomienie.',
        url: '/dashboard'
    };

    if (event.data) {
        try {
            const parsed = event.data.json();
            payload.title = parsed.title || payload.title;
            payload.body = parsed.body || payload.body;
            payload.url = parsed.url || payload.url;
        } catch (e) {
            payload.body = event.data.text() || payload.body;
        }
    }

    const options = {
        body: payload.body,
        icon: '/static/favicon.svg',
        badge: '/static/favicon.svg',
        vibrate: [150, 75, 150],
        data: { url: payload.url }
    };

    event.waitUntil(
        self.registration.showNotification(payload.title, options)
    );
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    const targetUrl = (event.notification.data && event.notification.data.url) || '/dashboard';

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
            for (const client of clientList) {
                if (client.url.includes(targetUrl) && 'focus' in client) {
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(targetUrl);
            }
        })
    );
});
