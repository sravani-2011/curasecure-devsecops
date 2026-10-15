(async function () {
  'use strict';
  const user = await CS.ready; if (!user) return;
  const { esc, api } = CS;
  const r = await api('/api/security');
  if (!r.available) { document.getElementById('none').classList.remove('hidden'); return; }
  document.getElementById('report').classList.remove('hidden');

  const v = document.getElementById('verdict');
  v.textContent = r.gatePassed ? 'PASSED' : 'BLOCKED';
  v.className = 'big ' + (r.gatePassed ? 'verdict-pass' : 'verdict-fail');
  document.getElementById('meta').innerHTML = [
    ['Jenkins build', `#${esc(r.build)}`], ['Commit', `<span class="mono">${esc(r.commit)}</span>`],
    ['Image', `<span class="mono">${esc(r.image)}</span>`], ['SBOM', `${esc(r.sbom?.components ?? '—')} components (${esc(r.sbom?.format || 'CycloneDX')})`],
    ['Scanned', esc(CS.fmt(r.generatedAt))],
  ].map(([k, x]) => `<dt>${esc(k)}</dt><dd>${x}</dd>`).join('');

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const sevCls = { critical: 'b-bad', high: 'b-bad', medium: 'b-warn', low: 'b-info', info: 'b-muted' };
  const resCls = { pass: 'b-ok', fail: 'b-bad', warn: 'b-warn', skipped: 'b-muted' };
  document.getElementById('gates').innerHTML = r.gates.map(g => {
    const counts = sevOrder.filter(s => g.counts[s]).map(s => `<span class="badge ${sevCls[s]}">${g.counts[s]} ${s}</span>`).join(' ') || '<span class="badge b-ok">0 findings</span>';
    return `<tr><td><b>${esc(g.name)}</b></td><td class="mono">${esc(g.tool)}</td><td>${esc(g.policy)}</td><td><div class="sev">${counts}</div></td><td><span class="badge ${resCls[g.status] || 'b-muted'}">${esc(g.status)}</span></td></tr>`;
  }).join('');

  const all = r.gates.flatMap(g => (g.findings || []).map(f => ({ ...f, scanner: g.tool })));
  all.sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  document.getElementById('findings').innerHTML = all.slice(0, 40).map(f => `<tr><td><span class="badge ${sevCls[f.severity] || 'b-muted'}">${esc(f.severity)}</span></td>
    <td class="mono">${esc(f.scanner)}</td><td class="mono">${esc(f.id)}</td><td>${esc(f.title)}</td><td class="mono">${esc(f.location)}</td></tr>`).join('')
    || '<tr><td colspan="5" class="empty">No findings. All scanners came back clean.</td></tr>';
})();
