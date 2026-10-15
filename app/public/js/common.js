// Shared layout, API helper and auth guard. No inline scripts anywhere (strict CSP).
(function () {
  'use strict';
  const page = document.body.dataset.page;
  const needsAuth = document.body.dataset.auth === 'required';

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function api(url, opts = {}) {
    const res = await fetch(url, {
      credentials: 'same-origin',
      headers: opts.body ? { 'Content-Type': 'application/json' } : {},
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    if (res.status === 401 && needsAuth) { location.href = '/login'; throw new Error('auth'); }
    if (!res.ok) { const e = new Error(data.error || `HTTP ${res.status}`); e.status = res.status; throw e; }
    return data;
  }

  const shield = '<svg class="shield" viewBox="0 0 30 34" aria-hidden="true"><path d="M15 1 28 6v10c0 8-5.6 14.4-13 17C7.6 30.4 2 24 2 16V6z" fill="#14b8a6"/><path d="M13 10h4v5h5v4h-5v5h-4v-5H8v-4h5z" fill="#0b2530"/></svg>';

  function nav(user) {
    const links = user
      ? [['/dashboard', 'Patients', 'dashboard'], ...(user.role === 'admin' ? [['/audit', 'Audit trail', 'audit']] : []), ['/security', 'Security Center', 'security']]
      : [['/', 'Overview', 'home'], ['/login', 'Sign in', 'login']];
    const el = document.createElement('header');
    el.innerHTML = `<div class="demo-banner">Fictional demonstration system. All patients and data are synthetic; no real health information.</div>
      <nav class="nav"><div class="wrap">
        <a class="brand" href="${user ? '/dashboard' : '/'}">${shield}CuraSecure</a>
        <button class="burger" aria-label="Menu">&#9776;</button>
        <ul class="nav-links">${links.map(([h, t, k]) => `<li><a href="${h}" class="${k === page ? 'on' : ''}">${t}</a></li>`).join('')}
          ${user ? `<li class="who"><span>${esc(user.name)}</span><span class="role">${esc(user.role)}</span><button class="btn btn-light" id="logout">Sign out</button></li>` : ''}
        </ul></div></nav>`;
    document.body.prepend(el);
    el.querySelector('.burger').addEventListener('click', () => el.querySelector('.nav-links').classList.toggle('open'));
    const lo = el.querySelector('#logout');
    if (lo) lo.addEventListener('click', async () => { await api('/api/auth/logout', { method: 'POST', body: {} }).catch(() => {}); location.href = '/login'; });
  }

  function footer() {
    const f = document.createElement('footer');
    f.innerHTML = '<div class="wrap"><span><b>CuraSecure</b> · DevSecOps implementation for a healthcare system · Jenkins · Docker · Kubernetes</span><span id="build-info"></span></div>';
    document.body.append(f);
    fetch('/api/build').then(r => r.json()).then(b => { document.getElementById('build-info').textContent = `build #${b.buildNumber} · ${b.version}`; }).catch(() => {});
  }

  window.CS = { esc, api, user: null, ready: null,
    fmt: iso => new Date(iso).toLocaleString(),
  };

  CS.ready = (async () => {
    let user = null;
    try { user = (await fetch('/api/auth/me', { credentials: 'same-origin' }).then(r => (r.ok ? r.json() : null)))?.user || null; } catch { /* offline */ }
    if (needsAuth && !user) { location.href = '/login'; return null; }
    if (page === 'login' && user) { location.href = '/dashboard'; return user; }
    CS.user = user;
    nav(needsAuth ? user : null);
    footer();
    return user;
  })();
})();
