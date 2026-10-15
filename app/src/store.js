// In-memory data store with FICTIONAL demo data (no real patients).
// Sensitive fields are stored only as AES-256-GCM ciphertext.
const bcrypt = require('bcryptjs');
const { encrypt, decrypt, mask } = require('./crypto');
const { demoPassword } = require('./config');

const SENSITIVE = ['nationalId', 'phone', 'address', 'diagnosis'];

// ---- Users (role-based access control) ----
const hash = bcrypt.hashSync(demoPassword, 10);
const users = {
  'dr.mehta':    { username: 'dr.mehta',    name: 'Dr. Arjun Mehta',  role: 'doctor', hash },
  'dr.fernandes':{ username: 'dr.fernandes',name: 'Dr. Leena Fernandes', role: 'doctor', hash },
  'nurse.priya': { username: 'nurse.priya', name: 'Priya Nair, RN',    role: 'nurse',  hash },
  'admin.rao':   { username: 'admin.rao',   name: 'Kiran Rao',         role: 'admin',  hash },
};
const failed = {}; // username -> { count, lockedUntil }

// ---- Patients (fictional) ----
const seed = [
  ['MRN-100231', 'Ananya Sharma', '1987-03-14', 'F', 'B+', 'Type 2 diabetes mellitus', ['Penicillin'], ['Metformin 500 mg BID'], 'dr.mehta', '900-12-4471', '+91 00000 11223', '12 Lake View Rd, Chennai', [78, 128, 82, 36.8, 98]],
  ['MRN-100232', 'Rohan Iyer', '1975-11-02', 'M', 'O+', 'Essential hypertension', [], ['Amlodipine 5 mg OD'], 'dr.mehta', '900-45-1188', '+91 00000 33445', '4 Temple St, Madurai', [84, 148, 94, 37.0, 97]],
  ['MRN-100233', 'Meera Pillai', '1992-07-21', 'F', 'A-', 'Asthma, moderate persistent', ['Aspirin'], ['Budesonide inhaler', 'Salbutamol PRN'], 'dr.fernandes', '900-77-3021', '+91 00000 55667', '9 Beach Rd, Kochi', [92, 118, 76, 37.2, 95]],
  ['MRN-100234', 'Vikram Reddy', '1960-01-30', 'M', 'AB+', 'Coronary artery disease', ['Sulfa drugs'], ['Atorvastatin 40 mg', 'Clopidogrel 75 mg'], 'dr.fernandes', '900-23-9054', '+91 00000 77889', '22 Hill Top, Hyderabad', [66, 132, 84, 36.6, 96]],
  ['MRN-100235', 'Sara Thomas', '2001-09-09', 'F', 'O-', 'Iron-deficiency anaemia', [], ['Ferrous sulfate 325 mg'], 'dr.mehta', '900-61-7402', '+91 00000 99001', '7 Garden Ave, Bengaluru', [88, 110, 70, 36.9, 99]],
  ['MRN-100236', 'Imran Khan', '1983-05-17', 'M', 'B-', 'Chronic kidney disease, stage 2', ['Ibuprofen'], ['Losartan 50 mg'], 'dr.fernandes', '900-38-5516', '+91 00000 22113', '31 Fort Rd, Mumbai', [74, 138, 88, 36.7, 98]],
];

const patients = new Map();
for (const [mrn, name, dob, sex, blood, diagnosis, allergies, meds, doctor, nationalId, phone, address, v] of seed) {
  patients.set(mrn, {
    mrn, name, dob, sex, bloodType: blood, allergies, medications: meds, assignedDoctor: doctor,
    enc: { nationalId: encrypt(nationalId), phone: encrypt(phone), address: encrypt(address), diagnosis: encrypt(diagnosis) },
    vitals: [{ at: new Date(Date.now() - 86400000).toISOString(), by: 'nurse.priya', heartRate: v[0], systolic: v[1], diastolic: v[2], temperature: v[3], spo2: v[4] }],
    notes: [], // each: { at, by, enc }
  });
}

// ---- Role-based views (minimum necessary access) ----
function view(p, role) {
  const base = { mrn: p.mrn, name: p.name, assignedDoctor: p.assignedDoctor };
  if (role === 'admin') {
    return { ...base, access: 'administrative (no clinical data)' };
  }
  const clinical = {
    ...base, dob: p.dob, sex: p.sex, bloodType: p.bloodType, allergies: p.allergies, medications: p.medications,
    diagnosis: decrypt(p.enc.diagnosis), vitals: p.vitals,
  };
  if (role === 'doctor') {
    return {
      ...clinical, access: 'full',
      nationalId: decrypt(p.enc.nationalId), phone: decrypt(p.enc.phone), address: decrypt(p.enc.address),
      notes: p.notes.map(n => ({ at: n.at, by: n.by, text: decrypt(n.enc) })),
    };
  }
  if (role === 'nurse') {
    return {
      ...clinical, access: 'clinical (identifiers masked, no physician notes)',
      nationalId: mask(decrypt(p.enc.nationalId)), phone: mask(decrypt(p.enc.phone)), address: 'restricted',
    };
  }
  return null;
}

function listPatients(role) { return [...patients.values()].map(p => view(p, role)); }
function getPatient(mrn, role) { const p = patients.get(mrn); return p ? view(p, role) : undefined; }
function rawRecord(mrn) {
  const p = patients.get(mrn);
  if (!p) return undefined;
  return { mrn: p.mrn, storedAs: p.enc, notes: p.notes.map(n => ({ at: n.at, by: n.by, enc: n.enc })) };
}
function addNote(mrn, by, text) {
  const p = patients.get(mrn); if (!p) return false;
  p.notes.unshift({ at: new Date().toISOString(), by, enc: encrypt(text) });
  return true;
}
function addVitals(mrn, by, v) {
  const p = patients.get(mrn); if (!p) return false;
  p.vitals.unshift({ at: new Date().toISOString(), by, ...v });
  p.vitals = p.vitals.slice(0, 20);
  return true;
}

module.exports = { users, failed, patients, SENSITIVE, listPatients, getPatient, rawRecord, addNote, addVitals };
