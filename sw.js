// Service Worker for ASPD Forum
const CACHE_NAME = 'aspd-forum-v7';
const OFFLINE_CACHE = 'aspd-forum-offline-v2';
const THREAD_CACHE = 'aspd-forum-threads-v2';

const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/login.html',
  '/register.html',
  '/forum.html',
  '/room.html',
  '/thread.html',
  '/profile.html',
  '/messages.html',
  '/search.html',
  '/activity.html',
  '/history.html',
  '/admin.html',
  '/avatar.html',
  '/css/style.css',
  '/js/utils.js',
  '/js/auth-state.js',
  '/js/notify.js',
  '/js/notifications.js',
  '/js/ui-components.js',
  '/js/avatar-renderer.js',
  '/js/websocket.js',
  '/favicon.svg',
  '/offline.html' // Dedicated offline page
];

// Helper to safely open cache (handles storage errors)
async function safeOpenCache(cacheName) {
  try {
    return await caches.open(cacheName);
  } catch (err) {
    console.warn('[SW] Cache open failed:', err.message);
    return null;
  }
}

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    safeOpenCache(CACHE_NAME)
      .then((cache) => {
        if (!cache) {
          console.warn('[SW] Install: Cache unavailable, skipping');
          return self.skipWaiting();
        }
        return cache.addAll(STATIC_ASSETS)
          .then(() => self.skipWaiting())
          .catch((err) => {
            console.warn('[SW] Install: Cache addAll failed:', err.message);
            return self.skipWaiting();
          });
      })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  const validCaches = [CACHE_NAME, OFFLINE_CACHE, THREAD_CACHE];
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => !validCaches.includes(name))
            .map((name) => caches.delete(name).catch(() => {}))
        );
      })
      .then(() => self.clients.claim())
      .catch((err) => {
        console.warn('[SW] Activate error:', err.message);
        return self.clients.claim();
      })
  );
});

// Fetch event - network first, cache fallback for HTML/CSS/JS
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // Skip non-http(s) schemes (chrome-extension://, etc.)
  if (!url.protocol.startsWith('http')) return;

  // Skip external URLs (Google Fonts, CDNs, etc.) - let browser handle them
  if (url.origin !== self.location.origin) return;

  // Handle API calls for thread data - cache for offline reading
  if (url.pathname.match(/^\/api\/threads\/[^/]+\/entries/)) {
    event.respondWith(handleThreadRequest(request));
    return;
  }

  // Handle room thread listings - cache for browsing offline
  if (url.pathname.match(/^\/api\/rooms\/[^/]+\/threads/)) {
    event.respondWith(handleRoomThreadsRequest(request));
    return;
  }

  // Skip other API calls (always fetch fresh)
  if (url.pathname.startsWith('/api/') || 
      url.pathname.startsWith('/login') ||
      url.pathname.startsWith('/register')) {
    return;
  }

  // For static assets and HTML, use stale-while-revalidate strategy
  event.respondWith(
    safeOpenCache(CACHE_NAME).then((cache) => {
      // If cache is unavailable, just fetch from network
      if (!cache) {
        return fetch(request).catch(() => {
          // Return a basic offline response
          return new Response('Offline - please check your connection', {
            status: 503,
            headers: { 'Content-Type': 'text/plain' }
          });
        });
      }
      
      return cache.match(request).then((cachedResponse) => {
        const fetchPromise = fetch(request)
          .then((networkResponse) => {
            // Cache successful responses
            if (networkResponse && networkResponse.status === 200) {
              cache.put(request, networkResponse.clone()).catch(() => {});
            }
            return networkResponse;
          })
          .catch(() => {
            // Network failed, return cached or offline page
            if (cachedResponse) return cachedResponse;
            
            // Return offline page for HTML requests
            if (request.headers.get('accept')?.includes('text/html')) {
              return cache.match('/offline.html').catch(() => {
                return new Response('Offline', { status: 503 });
              });
            }
            return cachedResponse;
          });

        // Return cached response immediately if available, or wait for network
        return cachedResponse || fetchPromise;
      }).catch(() => {
        // Cache match failed, try network
        return fetch(request);
      });
    }).catch(() => {
      // Complete failure, try network directly
      return fetch(request);
    })
  );
});

// Handle thread data requests with offline caching
async function handleThreadRequest(request) {
  try {
    const cache = await safeOpenCache(THREAD_CACHE);
    
    try {
      const networkResponse = await fetch(request);
      if (networkResponse && networkResponse.status === 200 && cache) {
        // Cache the thread data for offline reading
        cache.put(request, networkResponse.clone()).catch(() => {});
      }
      return networkResponse;
    } catch (err) {
      // Network failed, try cache
      if (cache) {
        const cachedResponse = await cache.match(request);
        if (cachedResponse) {
          // Add offline indicator to response
          const data = await cachedResponse.clone().json();
          data._offline = true;
          data._cachedAt = cachedResponse.headers.get('date');
          return new Response(JSON.stringify(data), {
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
      // Return error response if no cache
      return new Response(JSON.stringify({ 
        success: false, 
        error: 'offline',
        message: 'You are offline and this thread is not cached'
      }), { 
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (err) {
    // Cache API completely failed, try network
    return fetch(request).catch(() => {
      return new Response(JSON.stringify({ 
        success: false, 
        error: 'offline'
      }), { 
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    });
  }
}

// Handle room thread listings with caching
async function handleRoomThreadsRequest(request) {
  try {
    const cache = await safeOpenCache(OFFLINE_CACHE);
    
    try {
      const networkResponse = await fetch(request);
      if (networkResponse && networkResponse.status === 200 && cache) {
        cache.put(request, networkResponse.clone()).catch(() => {});
      }
      return networkResponse;
    } catch (err) {
      if (cache) {
        const cachedResponse = await cache.match(request);
        if (cachedResponse) {
          const data = await cachedResponse.clone().json();
          data._offline = true;
          return new Response(JSON.stringify(data), {
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
      return new Response(JSON.stringify({ 
        success: false, 
        error: 'offline' 
      }), { 
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  } catch (err) {
    return fetch(request).catch(() => {
      return new Response(JSON.stringify({ 
        success: false, 
        error: 'offline' 
      }), { 
        status: 503,
        headers: { 'Content-Type': 'application/json' }
      });
    });
  }
}

// Handle background sync for offline posts
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-posts') {
    event.waitUntil(syncOfflinePosts());
  }
});

// Sync offline posts when connection is restored
async function syncOfflinePosts() {
  try {
    const cache = await safeOpenCache(OFFLINE_CACHE);
    if (!cache) return;
    
    const requests = await cache.keys();
    
    for (const request of requests) {
      if (request.url.includes('pending-post')) {
        try {
          const data = await cache.match(request).then(r => r.json());
          
          const response = await fetch(data.url, {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': data.auth 
            },
            body: JSON.stringify(data.body)
          });
          
          if (response.ok) {
            // Remove from cache on success
            await cache.delete(request).catch(() => {});
            
            // Notify clients
            const clients = await self.clients.matchAll();
            clients.forEach(client => {
              client.postMessage({
                type: 'SYNC_COMPLETE',
                data: { url: data.url, success: true }
              });
            });
          }
        } catch (err) {
          console.error('[SW] Sync failed:', err);
        }
      }
    }
  } catch (err) {
    console.warn('[SW] syncOfflinePosts error:', err.message);
  }
}

// Handle messages from clients
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SAVE_FOR_OFFLINE') {
    // Save thread for offline reading
    safeOpenCache(THREAD_CACHE).then(cache => {
      if (!cache) return;
      fetch(event.data.url).then(response => {
        if (response.ok) {
          cache.put(event.data.url, response).catch(() => {});
        }
      }).catch(() => {});
    });
  }
  
  if (event.data && event.data.type === 'QUEUE_POST') {
    // Queue a post for when online
    safeOpenCache(OFFLINE_CACHE).then(cache => {
      if (!cache) return;
      const key = new Request('pending-post-' + Date.now());
      cache.put(key, new Response(JSON.stringify(event.data.post))).catch(() => {});
    });
  }
  
  if (event.data && event.data.type === 'CLEAR_THREAD_CACHE') {
    // Clear thread cache
    caches.delete(THREAD_CACHE).catch(() => {});
  }
});

// Handle push notifications (future use)
self.addEventListener('push', (event) => {
  if (!event.data) return;

  const data = event.data.json();
  const options = {
    body: data.body || 'New notification',
    icon: '/favicon.svg',
    badge: '/favicon.svg',
    vibrate: [100, 50, 100],
    tag: data.tag || 'aspd-notification',
    renotify: true,
    data: {
      url: data.url || '/forum.html'
    },
    actions: [
      { action: 'view', title: 'VIEW' },
      { action: 'dismiss', title: 'DISMISS' }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'ASPD Forum', options)
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  if (event.action === 'dismiss') return;

  event.waitUntil(
    clients.matchAll({ type: 'window' }).then((clientList) => {
      // Focus existing window if open
      for (const client of clientList) {
        if ('focus' in client) {
          client.focus();
          if (event.notification.data && event.notification.data.url) {
            client.navigate(event.notification.data.url);
          }
          return;
        }
      }
      // Open new window
      if (clients.openWindow) {
        return clients.openWindow(event.notification.data?.url || '/forum.html');
      }
    })
  );
});
