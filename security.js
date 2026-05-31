// ╔══════════════════════════════════════════════════════════╗
// ║  LUNEX SECURITY LAYER                                      ║
// ║  Client-side hardening: XSS, spam, integrity, clickjack    ║
// ╚══════════════════════════════════════════════════════════╝
(function () {
  'use strict';

  var LunexSec = {};

  // ── 1. CLICKJACKING PROTECTION (frame-busting) ────────────
  // Prevent the app being embedded in a malicious iframe
  try {
    if (window.top !== window.self) {
      window.top.location = window.self.location;
    }
  } catch (e) {
    // If we can't access top, we're sandboxed in a hostile frame → block
    document.documentElement.style.display = 'none';
  }

  // ── 2. XSS / INJECTION SANITIZATION ───────────────────────
  // Patterns that should never appear in stored user content
  var DANGEROUS = [
    /<\s*script/i,
    /<\s*\/\s*script/i,
    /javascript\s*:/i,
    /data\s*:\s*text\/html/i,
    /\bon\w+\s*=/i,            // onerror=, onclick=, onload=...
    /<\s*iframe/i,
    /<\s*img[^>]*\bon\w+/i,
    /<\s*svg[^>]*\bon\w+/i,
    /document\s*\.\s*cookie/i,
    /localStorage\s*\./i,
    /\beval\s*\(/i
  ];

  // Escape HTML entities (defense-in-depth even after filtering)
  LunexSec.escapeHtml = function (str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  // Returns { ok:true, text } or { ok:false, reason }
  LunexSec.sanitizeMessage = function (raw, maxLen) {
    maxLen = maxLen || 2000;
    if (typeof raw !== 'string') return { ok: false, reason: 'Invalid input type' };
    var text = raw.trim();
    if (!text) return { ok: false, reason: 'Empty message' };
    if (text.length > maxLen) return { ok: false, reason: 'Message too long (max ' + maxLen + ')' };
    for (var i = 0; i < DANGEROUS.length; i++) {
      if (DANGEROUS[i].test(text)) {
        return { ok: false, reason: 'Blocked: potentially malicious content detected' };
      }
    }
    return { ok: true, text: text };
  };

  // ── 3. RATE LIMITING (anti-spam) ──────────────────────────
  // Sliding window: max N actions per window per action-type
  var _buckets = {};
  LunexSec.rateLimit = function (key, max, windowMs) {
    max = max || 5;
    windowMs = windowMs || 5000;
    var now = Date.now();
    if (!_buckets[key]) _buckets[key] = [];
    // drop timestamps outside window
    _buckets[key] = _buckets[key].filter(function (t) { return now - t < windowMs; });
    if (_buckets[key].length >= max) {
      return { ok: false, reason: 'Slow down — too many actions', retryIn: windowMs - (now - _buckets[key][0]) };
    }
    _buckets[key].push(now);
    return { ok: true };
  };

  // ── 4. SESSION INTEGRITY ──────────────────────────────────
  // Detect tampering with the session object shape
  LunexSec.validateSession = function (session) {
    if (!session || typeof session !== 'object') return false;
    if (typeof session.username !== 'string' || !session.username) return false;
    if (session.username.length > 64) return false;
    // username must be alphanumeric-ish (matches register rules)
    if (!/^[\w.\- @]+$/.test(session.username)) return false;
    return true;
  };

  // ── 5. SAFE JSON PARSE (prevents prototype pollution) ─────
  LunexSec.safeParse = function (raw, fallback) {
    try {
      var parsed = JSON.parse(raw);
      // strip __proto__ / constructor pollution
      if (parsed && typeof parsed === 'object') {
        delete parsed.__proto__;
        delete parsed.constructor;
      }
      return parsed;
    } catch (e) {
      return fallback;
    }
  };

  // ── 6. STORAGE NAMESPACE GUARD ────────────────────────────
  // Only allow keys under the lunex_ namespace to be written via helper
  LunexSec.safeSet = function (key, value) {
    if (typeof key !== 'string' || key.indexOf('lunex_') !== 0) {
      console.warn('[LunexSec] Blocked write to non-lunex key:', key);
      return false;
    }
    localStorage.setItem(key, value);
    return true;
  };

  // ── 7. CONSOLE WARNING (anti self-XSS / scam) ─────────────
  setTimeout(function () {
    var s1 = 'color:#fff;font-size:22px;font-weight:900;text-shadow:0 0 10px #fff;';
    var s2 = 'color:#f55;font-size:14px;';
    console.log('%c⚠ STOP', s1);
    console.log('%cThis is a browser feature intended for developers. Do NOT paste any code here — it could let attackers steal your account or messages. (Self-XSS protection)', s2);
  }, 800);

  // Expose globally
  window.LunexSec = LunexSec;
})();
