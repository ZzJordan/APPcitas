/**
 * Global Notification System for Cupido's Project
 * Listens for real-time messages and pending offline messages.
 */

if (typeof socket !== 'undefined') {
    // 1. Create container if not exists
    let toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toast-container';
        document.body.appendChild(toastContainer);
    }

    // 2. Helper to show toast
    window.showGlobalToast = function (title, body, url) {
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
        };

        toastContainer.appendChild(toast);

        // Auto remove
        setTimeout(() => {
            toast.classList.add('toast-fade-out');
            setTimeout(() => toast.remove(), 400);
        }, 5000);
    };

    // 3. Listen for Global Alerts
    socket.on('global-message-alert', (data) => {
        // Don't show if we are ALREADY in that specific chat room
        if (window.location.pathname.includes(`/chat/${data.otherLink}`)) return;

        showGlobalToast(data.title, data.body, `/chat/${data.otherLink}`);

        // Vibration if available
        if (navigator.vibrate) navigator.vibrate([100, 50, 100]);
    });

    // 4. Listen for Pending (Offline) Messages
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
