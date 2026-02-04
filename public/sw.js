const CACHE_NAME = 'cupido-project-v2';
const ASSETS = [
    '/',
    '/index.html',
    '/login.html',
    '/dashboard.html',
    '/cupido-dashboard.html',
    '/blinder-matches.html',
    '/chat.html',

    '/style.css',
    '/manifest.json',
    '/app-icon.png',
    'https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&display=swap'
];

// Install Event
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            const SAFE_ASSETS = ASSETS.filter(a => !a.startsWith('http'));
            return cache.addAll(SAFE_ASSETS).catch(err => {
                console.warn("SW Precache warning:", err);
            });
        })
    );
    // Force immediate activation
    self.skipWaiting();
});

// Activate Event
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
            );
        })
    );
    // Force immediate control
    self.clients.claim();
});

// Fetch Event
self.addEventListener('fetch', (event) => {
    // 1. Navigation Requests (HTML): Network First, Fallback to Cache
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request)
                .then((networkResponse) => {
                    return caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, networkResponse.clone());
                        return networkResponse;
                    });
                })
                .catch(() => {
                    return caches.match(event.request);
                })
        );
        return;
    }

    // 2. Static Assets: Cache First, Fallback to Network
    if (event.request.method === 'GET') {
        event.respondWith(
            caches.match(event.request).then((cachedResponse) => {
                if (cachedResponse) return cachedResponse;

                return fetch(event.request).then((response) => {
                    if (!response || response.status !== 200 || response.type !== 'basic') {
                        return response;
                    }
                    const responseToCache = response.clone();
                    // Cache dynamic GETs if likely static (heuristic or explicit list)
                    // For now, we only aggressively cache if in ASSETS, essentially.
                    // But to support dynamic images created by users, we might want to cache them too?
                    // Let's stick to the previous logic but safer:
                    // Only cache if it was in our ASSETS list or looks like an asset
                    const url = new URL(event.request.url);
                    if (ASSETS.includes(url.pathname)) {
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, responseToCache);
                        });
                    }
                    return response;
                });
            })
        );
    }
});

// --- Push Notifications ---
self.addEventListener('push', event => {
    const data = event.data.json();
    console.log('[SW] Push Received:', data);

    const title = data.title || 'Nuevo Mensaje';
    const options = {
        body: data.body || 'Tienes una nueva notificación.',
        icon: '/app-icon.png',
        badge: '/app-icon.png',
        data: { url: data.url || '/dashboard' },
        tag: data.tag || 'general'
    };

    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
    console.log('[SW] Notification Clicked');
    event.notification.close();

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
            // Check if there is already a window open with target URL
            const targetUrl = event.notification.data.url;

            for (let client of windowClients) {
                // If url matches roughly (ignoring query params if needed, but here we want exact chat)
                // For simplified UX, if any app window is open, focus it and navigate.
                if (client.url.includes(targetUrl) && 'focus' in client) {
                    return client.focus();
                }
                // Or just focus any open window and navigate
                if (client.url.includes(self.registration.scope) && 'focus' in client) {
                    client.focus();
                    return client.navigate(targetUrl);
                }
            }
            // If no window open, open new one
            if (clients.openWindow) {
                return clients.openWindow(targetUrl);
            }
        })
    );
});
