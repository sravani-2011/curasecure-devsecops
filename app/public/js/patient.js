(async function () {
  'use strict';
  const user = await CS.ready; if (!user) return;
  const { esc, api } = CS;
  const mrn = new URLSearchParams(location.search).get('mrn') || '';
  const $ = id => document.getElementById(id);
  const kv = rows => rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('');

  function msg(el, text, ok) { el.textContent = text; el.className = `alert ${ok ? 'alert-ok' : 'alert-err'}`; }

  async function load() {
    let p;
    try { p = (await api(`/api/patients/${encodeURIComponent(mrn)}`)).patient; }
    catch (e) { msg($('perr'), e.message, false); $('body').classList.add('hidden'); return; }

    $('pname').textContent = p.name;
    $('pmeta').innerHTML = `<span class="mono">${esc(p.mrn)}</span> · physician <span class="mono">${esc(p.assignedDoctor)}</span> · <span class="badge b-info">${esc(p.access)}</span>`;

    if (user.role === 'admin') {
      $('demo').innerHTML = kv([['MRN', esc(p.mrn)], ['Name', esc(p.name)], ['Physician', esc(p.assignedDoctor)]]);
      $('clin').innerHTML = kv([['Clinical data', '<span class="badge b-muted">not permitted for admin role</span>']]);
      $('vitals-sec').classList.add('hidden'); $('notes-sec').classList.add('hidden');
      const raw = await api(`/api/admin/encrypted/${encodeURIComponent(mrn)}`);
      $('raw').textContent = JSON.stringify(raw.storedAs, null, 2);
      $('raw-sec').classList.remove('hidden');
      return;
    }

    $('demo').innerHTML = kv([
      ['Date of birth', esc(p.dob)], ['Sex', esc(p.sex)], ['Blood type', esc(p.bloodType)],
      ['National ID', `<span class="mono">${esc(p.nationalId)}</span>`], ['Phone', `<span class="mono">${esc(p.phone)}</span>`],
      ['Address', esc(p.address)],
    ]);
    $('clin').innerHTML = kv([
      ['Diagnosis', esc(p.diagnosis)],
      ['Allergies', p.allergies.length ? p.allergies.map(a => `<span class="badge b-bad">${esc(a)}</span>`).join(' ') : 'None known'],
      ['Medications', p.medications.map(esc).join('<br>')],
    ]);
    $('vitals').innerHTML = p.vitals.map(v => `<tr><td>${esc(CS.fmt(v.at))}</td><td class="mono">${esc(v.by)}</td><td>${esc(v.heartRate)}</td>
      <td>${esc(v.systolic)}/${esc(v.diastolic)}</td><td>${esc(v.temperature)}</td><td>${esc(v.spo2)}%</td></tr>`).join('');
    $('vitals-form').classList.remove('hidden');

    if (user.role === 'doctor') {
      $('notes-hint').textContent = 'Visible to physicians only.';
      $('notes').innerHTML = p.notes.length ? p.notes.map(n => `<div class="note">${esc(n.text)}<br><small>${esc(n.by)} · ${esc(CS.fmt(n.at))}</small></div>`).join('') : '<p class="lead">No notes yet.</p>';
      $('note-form').classList.remove('hidden');
    } else {
      $('notes-hint').textContent = 'Physician notes are not available to your role (minimum necessary access).';
    }
  }

  $('vitals-form').addEventListener('submit', async e => {
    e.preventDefault();
    const f = e.target; const body = {};
    for (const k of ['heartRate', 'systolic', 'diastolic', 'temperature', 'spo2']) body[k] = f[k].value;
    try { await api(`/api/patients/${encodeURIComponent(mrn)}/vitals`, { method: 'POST', body }); f.reset(); msg($('vmsg'), 'Vitals saved and audited.', true); load(); }
    catch (ex) { msg($('vmsg'), ex.message, false); }
  });
  $('note-form').addEventListener('submit', async e => {
    e.preventDefault();
    try { await api(`/api/patients/${encodeURIComponent(mrn)}/notes`, { method: 'POST', body: { text: $('note-text').value } }); $('note-text').value = ''; msg($('nmsg'), 'Note encrypted and saved.', true); load(); }
    catch (ex) { msg($('nmsg'), ex.message, false); }
  });

  load();
})();
