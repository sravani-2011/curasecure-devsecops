(function () {
  'use strict';
  const form = document.getElementById('login-form');
  const err = document.getElementById('err');
  form.addEventListener('submit', async e => {
    e.preventDefault();
    err.classList.add('hidden');
    const username = form.username.value.trim().toLowerCase();
    const password = form.password.value;
    try {
      await CS.api('/api/auth/login', { method: 'POST', body: { username, password } });
      location.href = '/dashboard';
    } catch (ex) {
      err.textContent = ex.message;
      err.classList.remove('hidden');
      form.password.value = '';
    }
  });
})();
