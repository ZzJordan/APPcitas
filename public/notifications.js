/**
 * Global Notification & Update System for Cupido's Project
 */

// --- 1. PWA Update & Registration Logic ---
if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        let isRefreshing = false;

        // Handle controller change (reload on update)
        navigator.serviceWorker.addEventListener('controllerchange', () => {
            if (isRefreshing) return;
            isRefreshing = true;
            window.location.reload();
        });

        navigator.serviceWorker.register('/sw.js').then(reg => {
            // Check for updates periodically
            setInterval(() => {
                reg.update();
            }, 60 * 60 * 1000); // Check every hour

            // Handle waiting worker
            if (reg.waiting) {
                notifyUpdate(reg.waiting);
                return;
            }

            reg.addEventListener('updatefound', () => {
                const newWorker = reg.installing;
                newWorker.addEventListener('statechange', () => {
                    if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                        notifyUpdate(newWorker);
                    }
                });
            });
        }).catch(err => console.log('SW error:', err));
    });
}

function notifyUpdate(worker) {
    // Since we use skipWaiting() in SW, this might fire very quickly.
    // Use a toast to inform the user if reload takes a moment, or just let the reload happen (controllerchange).
    // But since user requested "automatic", the SW skipWaiting + controllerchange -> reload is best.
    // We'll show a brief toast just in case.
    if (typeof window.showGlobalToast === 'function') {
        window.showGlobalToast("Actualizando...", "Aplicando nueva versión ✨", null);
    }
}


// --- 2. Toast UI System ---
if (typeof socket !== 'undefined') {
    // Create container if not exists
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        document.body.appendChild(toastContainer);
    }

    // Helper to show toast
    window.showGlobalToast = function (title, body, url) {
        // Prevent duplicates
        if (document.querySelector('.toast-title')?.innerText === title) return;

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <div class="toast-icon">💬</div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-body">${body}</div>
            </div>
        `;

        toast.onclick = () => {
            if (url) window.location.href = url;
            toast.remove();
        };

        toastContainer.appendChild(toast);

        // Auto remove
        setTimeout(() => {
            toast.classList.add('toast-fade-out');
            setTimeout(() => toast.remove(), 400);
        }, 5000);
    };

    // Listen for Global Alerts
    socket.on('global-message-alert', (data) => {
        // Don't show if we are ALREADY in that specific chat room
        if (window.location.pathname.includes(`/chat/${data.otherLink}`)) return;

        showGlobalToast(data.title, data.body, `/chat/${data.otherLink}`);

        // Vibration if available
        if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
    });

    // Listen for Pending (Offline) Messages
    socket.on('pending-messages', (messages) => {
        if (!messages || messages.length === 0) return;

        const count = messages.length;
        const lastMsg = messages[messages.length - 1];

        setTimeout(() => {
            showGlobalToast(
                `Tienes ${count} mensaje${count > 1 ? 's' : ''} nuevo${count > 1 ? 's' : ''}`,
                count > 1 ? 'Pulsa para verlo todo.' : lastMsg.body,
                `/chat/${lastMsg.otherLink}`
            );
        }, 1500); // Slight delay for better UX after login
    });
}
