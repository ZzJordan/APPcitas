const CACHE_NAME = 'cupido-project-v1';
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
    'https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&display=swap'
];

// Install Event
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            // We use 'addAll' inside a try-catch equivalent by mapping.
            // If one fails, we log it but don't crash the whole SW if possible, 
            // OR we stick to addAll but ensure the list is clean.
            // Google Fonts (external) can sometimes cause CORS issues in SW addAll if not CORS-enabled transparently.
            // Removing external font from explicit pre-cache is often safer.
            const SAFE_ASSETS = ASSETS.filter(a => !a.startsWith('http'));
            return cache.addAll(SAFE_ASSETS).catch(err => {
                console.warn("SW Precache warning:", err);
            });
        })
    );
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
    self.clients.claim();
});

// Fetch Event
self.addEventListener('fetch', (event) => {
    // Solo cachear peticiones GET
    if (event.request.method !== 'GET') return;

    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            if (cachedResponse) return cachedResponse;

            return fetch(event.request).then((response) => {
                // No cachear si no es una respuesta válida
                if (!response || response.status !== 200 || response.type !== 'basic') {
                    return response;
                }

                // Clonar la respuesta para guardarla en caché si es un asset estático
                const responseToCache = response.clone();
                const url = new URL(event.request.url);
                if (ASSETS.includes(url.pathname)) {
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseToCache);
                    });
                }

                return response;
            }).catch(() => {
                // Si falla el fetch y no hay caché, podríamos devolver una página offline dedicada aquí
            });
        })
    );
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
