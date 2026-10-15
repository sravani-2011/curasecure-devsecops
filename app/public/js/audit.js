(async function () {
  'use strict';
  const user = await CS.ready; if (!user) return;
  const { esc, api } = CS;
  let data;
  try { data = await api('/api/audit'); }
  catch (e) { const el = document.getElementById('aerr'); el.textContent = e.message; el.classList.remove('hidden'); return; }

  const es = data.entries;
  const count = f => es.filter(f).length;
  document.getElementById('astats').innerHTML = [
    ['Hash chain', data.chainValid ? '<span class="badge b-ok">intact</span>' : '<span class="badge b-bad">broken</span>'],
    ['Events', es.length],
    ['Denied / failed', count(e => e.outcome !== 'success')],
    ['Record views', count(e => e.action === 'patient.view')],
  ].map(([k, v]) => `<div class="card"><p>${esc(k)}</p><h3 class="u-stat">${typeof v === 'number' ? v : v}</h3></div>`).join('');

  const cls = o => (o === 'success' ? 'b-ok' : o === 'denied' ? 'b-bad' : 'b-warn');
  document.getElementById('arows').innerHTML = es.map(e => `<tr>
    <td class="mono">${esc(e.id)}</td><td>${esc(CS.fmt(e.at))}</td><td class="mono">${esc(e.user)}</td><td>${esc(e.role || '—')}</td>
    <td class="mono">${esc(e.action)}</td><td class="mono">${esc(e.target || '—')}</td><td><span class="badge ${cls(e.outcome)}">${esc(e.outcome)}</span></td>
    <td class="mono" title="${esc(e.hash)}">${esc(e.hash.slice(0, 12))}…</td></tr>`).join('') || '<tr><td colspan="8" class="empty">No events yet.</td></tr>';
})();
