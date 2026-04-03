/**
 * NCP WebSocket Client
 * Handles /ws namespace for real-time logs and stats.
 * Reconnects automatically with exponential backoff.
 */

class NCPWebSocket {
  constructor(opts = {}) {
    this.url = opts.url || null; // will use socket.io if null
    this.onLog = opts.onLog || null;
    this.onStats = opts.onStats || null;
    this.onModuleStats = opts.onModuleStats || null;
    this.onConnect = opts.onConnect || null;
    this.onDisconnect = opts.onDisconnect || null;

    this._socket = null;
    this._reconnectDelay = 1000;
    this._maxDelay = 16000;
    this._reconnectTimer = null;
    this._connected = false;
    this._destroyed = false;
  }

  connect() {
    if (this._destroyed) return;
    if (typeof io === 'undefined') {
      console.warn('[WS] Socket.IO not loaded — retrying in 2s');
      this._reconnectTimer = setTimeout(() => this.connect(), 2000);
      return;
    }

    try {
      // Determine the correct namespace path for socket.io
      const socketPath = this._getSocketPath();
      this._socket = io('/ws', {
        path: socketPath,
        transports: ['websocket', 'polling'],
        reconnection: false, // we handle reconnection ourselves
      });

      this._socket.on('connect', () => {
        this._connected = true;
        this._reconnectDelay = 1000;
        console.log('[WS] Connected');
        if (this.onConnect) this.onConnect();
      });

      this._socket.on('disconnect', (reason) => {
        this._connected = false;
        console.log('[WS] Disconnected:', reason);
        if (this.onDisconnect) this.onDisconnect(reason);
        if (!this._destroyed) this._scheduleReconnect();
      });

      this._socket.on('connect_error', (err) => {
        console.warn('[WS] Connection error:', err.message);
        if (!this._connected && !this._destroyed) this._scheduleReconnect();
      });

      this._socket.on('log', (entry) => {
        if (this.onLog) this.onLog(entry);
      });

      this._socket.on('stats', (data) => {
        if (this.onStats) this.onStats(data);
      });

      this._socket.on('module_stats', (data) => {
        if (this.onModuleStats) this.onModuleStats(data);
      });

    } catch (e) {
      console.error('[WS] Init error:', e);
      this._scheduleReconnect();
    }
  }

  _getSocketPath() {
    // When deployed behind a proxy, socket.io path includes the port prefix
    const base = document.querySelector('meta[name="api-base"]')?.content || '';
    if (base && base !== '/') {
      return base.replace(/\/+$/, '') + '/socket.io';
    }
    return '/socket.io';
  }

  _scheduleReconnect() {
    if (this._destroyed || this._reconnectTimer) return;
    this._reconnectTimer = setTimeout(() => {
      this._reconnectTimer = null;
      console.log(`[WS] Reconnecting (delay ${this._reconnectDelay}ms)...`);
      this._socket?.disconnect();
      this._socket = null;
      this.connect();
    }, this._reconnectDelay);
    this._reconnectDelay = Math.min(this._reconnectDelay * 2, this._maxDelay);
  }

  ping() {
    if (this._socket && this._connected) {
      this._socket.emit('ping', { ts: Date.now() });
    }
  }

  isConnected() { return this._connected; }

  destroy() {
    this._destroyed = true;
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    if (this._socket) {
      this._socket.disconnect();
      this._socket = null;
    }
  }
}

// Export for use in app.js
window.NCPWebSocket = NCPWebSocket;
