// ╔══════════════════════════════════════════════════════════╗
// ║  LUNEX · Shared client API + Socket.io helpers            ║
// ╚══════════════════════════════════════════════════════════╝
window.LunexApp = (function () {
  const API = window.location.origin;
  let token = localStorage.getItem('lunex_token');
  let me = null;
  let socket = null;
  const handlers = {};

  function on(event, fn) { (handlers[event] = handlers[event] || []).push(fn); }
  function emit(event, ...args) { (handlers[event] || []).forEach(fn => { try { fn(...args); } catch (e) {} }); }

  async function api(path, opts = {}) {
    opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    if (token) opts.headers.Authorization = 'Bearer ' + token;
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
    const r = await fetch(API + path, opts);
    const ct = r.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await r.json() : await r.text();
    if (!r.ok) throw new Error(data.error || data || ('HTTP ' + r.status));
    return data;
  }

  async function login(ident, password) {
    const data = await api('/api/login', { method: 'POST', body: { ident, password } });
    token = data.token; me = data.user;
    localStorage.setItem('lunex_token', token);
    localStorage.setItem('lunex_session', JSON.stringify({ username: me.username, email: ident, joined: new Date().toLocaleDateString() }));
    return me;
  }

  async function register(username, email, password) {
    const data = await api('/api/register', { method: 'POST', body: { username, email, password } });
    token = data.token; me = data.user;
    localStorage.setItem('lunex_token', token);
    localStorage.setItem('lunex_session', JSON.stringify({ username: me.username, email, joined: new Date().toLocaleDateString() }));
    return me;
  }

  async function loadMe() {
    if (!token) return null;
    try {
      me = await api('/api/me');
      return me;
    } catch (e) {
      logout();
      return null;
    }
  }

  function logout() {
    localStorage.removeItem('lunex_token');
    localStorage.removeItem('lunex_session');
    token = null; me = null;
    if (socket) { socket.disconnect(); socket = null; }
  }

  function getMe() { return me; }
  function getToken() { return token; }
  function isAdmin() { return me && (me.role === 'superadmin' || me.role === 'admin'); }

  // ── Socket.io connection ─────────────────────────────────
  function connect() {
    if (socket) return socket;
    if (!window.io) { console.warn('Socket.io not loaded'); return null; }
    socket = io({ auth: { token } });
    socket.on('connect', () => emit('connected'));
    socket.on('disconnect', () => emit('disconnected'));
    socket.on('connect_error', (e) => emit('error', e));
    socket.on('message:new', m => emit('message', m));
    socket.on('dm:new', m => emit('dm', m));
    socket.on('typing', d => emit('typing', d));
    socket.on('dm:typing', d => emit('dm-typing', d));
    socket.on('presence:online', list => emit('online', list));
    socket.on('channel:created', c => emit('channel-created', c));
    socket.on('channel:updated', c => emit('channel-updated', c));
    socket.on('channel:deleted', id => emit('channel-deleted', id));
    socket.on('user:role-changed', d => emit('role-changed', d));
    socket.on('reaction:update', d => emit('reaction', d));
    socket.on('user:muted', d => emit('muted', d));
    socket.on('user:unmuted', d => emit('unmuted', d));
    return socket;
  }

  function getSocket() { return socket || connect(); }

  // Convenience methods
  return {
    API, api, login, register, loadMe, logout, getMe, getToken, isAdmin,
    connect, getSocket, on,
    // server data shortcuts
    getChannels: () => api('/api/channels'),
    createChannel: (data) => api('/api/channels', { method: 'POST', body: data }),
    updateChannel: (id, data) => api('/api/channels/' + id, { method: 'PATCH', body: data }),
    deleteChannel: (id) => api('/api/channels/' + id, { method: 'DELETE' }),
    getMessages: (channelId, limit = 100) => api('/api/messages/' + encodeURIComponent(channelId) + '?limit=' + limit),
    sendMessage: (channelId, text, action) => new Promise((resolve, reject) => {
      const s = getSocket(); if (!s) return reject('No socket');
      s.emit('message:send', { channelId, text, action }, (resp) => {
        if (resp && resp.error) reject(resp.error); else resolve(resp.msg);
      });
    }),
    typing: (channelId) => { const s = getSocket(); if (s) s.emit('typing', { channelId }); },
    joinChannel: (channelId) => { const s = getSocket(); if (s) s.emit('channel:join', channelId); },
    leaveChannel: (channelId) => { const s = getSocket(); if (s) s.emit('channel:leave', channelId); },
    getDMs: (partner, limit = 200) => api('/api/dms/' + encodeURIComponent(partner) + '?limit=' + limit),
    getDMPartners: () => api('/api/dm-partners'),
    sendDM: (to, text, encrypted) => new Promise((resolve, reject) => {
      const s = getSocket(); if (!s) return reject('No socket');
      s.emit('dm:send', { to, text, encrypted: !!encrypted }, (resp) => {
        if (resp && resp.error) reject(resp.error); else resolve(resp.msg);
      });
    }),
    dmTyping: (to) => { const s = getSocket(); if (s) s.emit('dm:typing', { to }); },
    getUsers: () => api('/api/users'),
    setRole: (username, role) => api('/api/admin/role', { method: 'POST', body: { username, role } }),
    mute: (username, minutes, reason) => api('/api/admin/mute', { method: 'POST', body: { username, minutes, reason } }),
    unmute: (username) => api('/api/admin/unmute', { method: 'POST', body: { username } }),
    getMutes: () => api('/api/mutes'),
    loginAs: async (username) => {
      const data = await api('/api/admin/login-as', { method: 'POST', body: { username } });
      // swap to the impersonated session
      token = data.token;
      me = data.user;
      localStorage.setItem('lunex_token', token);
      localStorage.setItem('lunex_session', JSON.stringify({ username: me.username, email: me.email, joined: new Date().toLocaleDateString() }));
      return me;
    },
    toggleReaction: (messageId, emoji, channelId) => new Promise((resolve, reject) => {
      const s = getSocket(); if (!s) return reject('No socket');
      s.emit('reaction:toggle', { messageId, emoji, channelId }, (resp) => {
        if (resp && resp.error) reject(resp.error); else resolve(resp.reactions);
      });
    })
  };
})();
