/* Microsoft sign-in handoff. Only a short-lived proof is kept during sign-in. */
window.KomfortMicrosoft = (() => {
  const key = 'komfort_microsoft_pending';
  let finish, timer, busy = false, attempt = 0;
  const button = () => document.getElementById('microsoft-signin');
  const message = text => { document.getElementById('microsoft-status').textContent = text; };
  const base64 = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  function clear() {
    attempt++;
    sessionStorage.removeItem(key);
    clearTimeout(timer);
    button().disabled = false;
    document.getElementById('microsoft-cancel').hidden = true;
  }
  async function request(path, body) {
    const response = await fetch('/api/auth/microsoft/' + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Microsoft sign-in failed. Please try again.');
    return data;
  }
  async function complete() {
    if (busy) return false;
    const raw = sessionStorage.getItem(key);
    if (!raw) return false;
    busy = true;
    try {
      const pending = JSON.parse(raw);
      if (Date.now() > pending.expires) throw new Error('Microsoft sign-in timed out. Please try again.');
      const result = await request('complete', pending);
      // The user may have cancelled or started another attempt while waiting.
      if (sessionStorage.getItem(key) !== raw) return false;
      if (result.pending) {
        button().disabled = true;
        document.getElementById('microsoft-cancel').hidden = false;
        message('Finish signing in with Microsoft, then return to Expenses.');
        clearTimeout(timer);
        timer = setTimeout(complete, 2000);
        return false;
      }
      clear();
      message('');
      await finish(result);
      return true;
    } catch (error) {
      if (sessionStorage.getItem(key) === raw) { clear(); message(error.message); }
      return false;
    } finally { busy = false; }
  }
  async function start() {
    const currentAttempt = ++attempt;
    button().disabled = true;
    document.getElementById('microsoft-cancel').hidden = false;
    message('Connecting to Microsoft…');
    try {
      if (!crypto.subtle) throw new Error('Microsoft sign-in needs HTTPS or localhost.');
      const verifier = base64(crypto.getRandomValues(new Uint8Array(32)));
      const challenge = base64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
      // Capability is injected by the updated Android app on trusted pages only.
      const android = !!window.__komfortMicrosoftNative && !!window.KomfortAndroid;
      if (/KomfortExpensesApp\//.test(navigator.userAgent) && !android) {
        throw new Error('Please update the Expenses Android app to use Microsoft sign-in.');
      }
      const result = await request('start', { challenge, mode: android ? 'android' : 'web' });
      if (currentAttempt !== attempt) return;
      sessionStorage.setItem(key, JSON.stringify({ state: result.state, verifier, expires: Date.now() + 5 * 60 * 1000 }));
      if (android) {
        window.KomfortAndroid.postMessage(JSON.stringify({ type: 'microsoftSignIn', url: result.url }));
        await complete();
      } else {
        location.assign(result.url);
      }
    } catch (error) { if (currentAttempt === attempt) { clear(); message(error.message); } }
  }
  async function init(onSession) {
    finish = onSession;
    button().addEventListener('click', start);
    document.getElementById('microsoft-cancel').addEventListener('click', () => { clear(); message('Microsoft sign-in cancelled.'); });
    window.addEventListener('focus', () => { if (sessionStorage.getItem(key)) complete(); });
    document.addEventListener('visibilitychange', () => { if (!document.hidden) complete(); });
    try {
      const response = await fetch('/api/auth/microsoft/config', { cache: 'no-store', signal: AbortSignal.timeout(10000) });
      const config = await response.json();
      button().disabled = !config.enabled;
      if (!config.enabled) { message('Microsoft sign-in is not configured yet. Contact your finance administrator to restore Microsoft sign-in.'); return false; }
    } catch (_) { message('Microsoft sign-in is currently unavailable. Contact your finance administrator to restore Microsoft sign-in.'); return false; }
    const match = /^#microsoft=([A-Za-z0-9_-]{43})$/.exec(location.hash);
    if (match) {
      history.replaceState(null, '', location.pathname + location.search);
      let pending;
      try { pending = JSON.parse(sessionStorage.getItem(key)); } catch (_) {}
      if (pending?.state !== match[1]) { clear(); message('Please start Microsoft sign-in again in this browser.'); return false; }
    }
    return complete();
  }
  return { init, cancel: clear };
})();
