(async function () {
  'use strict';
  const user = await CS.ready; if (!user) return;
  const { esc } = CS;
  const notes = {
    doctor: 'Full access: identifiers, diagnosis and physician notes. Every record you open is written to the audit trail.',
    nurse: 'Clinical access: vitals, allergies, medications and diagnosis. National ID and phone are masked, and physician notes are hidden.',
    admin: 'Administrative access: no clinical data is visible to your role. Use the Audit trail to review PHI access.',
  };
  document.getElementById('greet').textContent = `Welcome, ${user.name}`;
  document.getElementById('access-note').textContent = notes[user.role] || '';

  const { patients } = await CS.api('/api/patients');
  const clinical = user.role !== 'admin';
  document.getElementById('thead').innerHTML = clinical
    ? '<tr><th>MRN</th><th>Patient</th><th>Age / Sex</th><th>Diagnosis</th><th>Allergies</th><th>Latest vitals</th><th>Physician</th><th></th></tr>'
    : '<tr><th>MRN</th><th>Patient</th><th>Physician</th><th>Access level</th><th></th></tr>';

  const age = dob => Math.floor((Date.now() - new Date(dob)) / 3.15576e10);
  document.getElementById('rows').innerHTML = patients.map(p => {
    const link = `<a href="/patient?mrn=${encodeURIComponent(p.mrn)}">Open →</a>`;
    if (!clinical) return `<tr><td class="mono">${esc(p.mrn)}</td><td>${esc(p.name)}</td><td class="mono">${esc(p.assignedDoctor)}</td><td><span class="badge b-muted">${esc(p.access)}</span></td><td>${link}</td></tr>`;
    const v = p.vitals[0] || {};
    const allergies = p.allergies.length ? p.allergies.map(a => `<span class="badge b-bad">${esc(a)}</span>`).join(' ') : '<span class="badge b-ok">none</span>';
    return `<tr><td class="mono">${esc(p.mrn)}</td><td><b>${esc(p.name)}</b></td><td>${age(p.dob)} / ${esc(p.sex)}</td><td>${esc(p.diagnosis)}</td>
      <td>${allergies}</td><td class="mono">HR ${esc(v.heartRate)} · BP ${esc(v.systolic)}/${esc(v.diastolic)} · SpO₂ ${esc(v.spo2)}%</td><td class="mono">${esc(p.assignedDoctor)}</td><td>${link}</td></tr>`;
  }).join('');

  const mine = patients.filter(p => p.assignedDoctor === user.username).length;
  const stats = [
    ['Patients visible', patients.length],
    ['Your role', user.role.toUpperCase()],
    [user.role === 'doctor' ? 'Assigned to you' : 'With allergies', user.role === 'doctor' ? mine : patients.filter(p => p.allergies && p.allergies.length).length],
    ['Session', '30 min, HttpOnly'],
  ];
  if (!clinical) stats[2] = ['Clinical fields shown', 0];
  document.getElementById('stats').innerHTML = stats.map(([k, v]) => `<div class="card"><p>${esc(k)}</p><h3 class="u-stat">${esc(v)}</h3></div>`).join('');
})();
