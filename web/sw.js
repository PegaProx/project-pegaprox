// PegaProx Service Worker
// MK May 2026 — wake-up push pattern + light static caching.
// Live data is NEVER cached — only static shell + images.
// On push event we fetch /api/push/inbox to show the freshest notification.

const CACHE_NAME = 'pegaprox-shell-v3';
const SHELL_ASSETS = [
  '/',
  '/manifest.webmanifest',
  '/images/pegaprox.png',
  '/favicon.ico',
];

self.addEventListener('install', (e) => {
  // pre-cache shell so the app boots offline. Failures are non-fatal.
  e.waitUntil(
    caches.open(CACHE_NAME).then(c => Promise.allSettled(SHELL_ASSETS.map(u => c.add(u))))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  // drop old caches
  e.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    )).then(() => self.clients.claim())
  );
});

// Network-only for /api/* (auth + live data must hit server).
// Network-first with cache fallback for static (so offline still loads shell).
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  if (url.origin !== self.location.origin) return;             // pass through external
  if (e.request.method !== 'GET') return;                       // pass through non-GET
  if (url.pathname.startsWith('/api/')) return;                 // pass through API
  if (url.pathname.startsWith('/ws')) return;                   // pass through ws
  if (url.pathname.startsWith('/.well-known/')) return;         // pass through ACME

  // For shell + static: try network, then cache, then show whatever we have.
  e.respondWith(
    fetch(e.request).then(resp => {
      // only cache successful basic GETs
      if (resp.ok && resp.type === 'basic') {
        const clone = resp.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone)).catch(() => {});
      }
      return resp;
    }).catch(() => caches.match(e.request).then(r => r || caches.match('/')))
  );
});

// Wake-up push: fetch the latest inbox entry and showNotification.
self.addEventListener('push', (e) => {
  e.waitUntil(
    fetch('/api/push/inbox?unread=1', { credentials: 'include' })
      .then(r => r.ok ? r.json() : { items: [] })
      .then(({ items }) => {
        if (!items || !items.length) {
          // wake-up arrived but nothing in inbox (could be a test or already-cleared)
          return self.registration.showNotification('PegaProx', {
            body: 'You have a new alert',
            icon: '/images/pegaprox.png',
            badge: '/images/pegaprox.png',
            tag: 'pegaprox-generic',
          });
        }
        // show only the freshest item (avoid spamming if many backed up)
        const item = items[0];
        const sev = (item.severity || 'info').toLowerCase();
        const opts = {
          body: item.body || '',
          icon: '/images/pegaprox.png',
          badge: '/images/pegaprox.png',
          tag: item.tag || `pegaprox-${item.id}`,
          renotify: true,
          requireInteraction: sev === 'critical',
          data: { url: item.url || '/', id: item.id },
        };
        return self.registration.showNotification(item.title || 'PegaProx', opts);
      })
      .catch(err => {
        // network down or session expired — best-effort generic notification
        return self.registration.showNotification('PegaProx', {
          body: 'New activity (open the app to view)',
          icon: '/images/pegaprox.png',
          tag: 'pegaprox-fallback',
        });
      })
  );
});

self.addEventListener('notificationclick', (e) => {
  const target = (e.notification.data && e.notification.data.url) || '/';
  e.notification.close();
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // focus an existing tab if one is open at our origin
      for (const c of list) {
        if (c.url.startsWith(self.location.origin)) {
          c.focus();
          if ('navigate' in c) c.navigate(target).catch(() => {});
          return;
        }
      }
      return clients.openWindow(target);
    })
  );
});
