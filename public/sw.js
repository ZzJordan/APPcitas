const CACHE_NAME = 'appcitas-v1';
const ASSETS = [
    '/',
    '/index.html',
    '/login.html',
    '/dashboard.html',
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
            return cache.addAll(ASSETS);
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
