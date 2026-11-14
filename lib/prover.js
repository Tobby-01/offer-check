// Groth16 proofs with the official Agent Games gatekeeper circuit (Circom 2 / BN128).
// The circuit recomputes the correct decision itself: a proof only exists for the
// decision the rules allow, so it doubles as a second, independent referee.
const path = require('path'), crypto = require('crypto');
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WASM = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
let snarkjs; const lazy = () => (snarkjs ||= require('snarkjs'));

function fe(v) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v === 'number') return Number.isSafeInteger(v) ? BigInt(v) % P : null;
  const s = String(v).trim();
  if (/^\d+$/.test(s)) return BigInt(s) % P;
  if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s) % P;
  return BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex')) % P;
}

function inputsFor(input, taskId, decision) {
  const g = (...ks) => { for (const k of ks) if (input[k] !== undefined && input[k] !== null && input[k] !== '') return input[k]; };
  const m = {
    minimum: g('minimum'), publicBalance: g('public_balance', 'publicBalance'), amount: g('amount'),
    expiryBlock: g('expiry_block', 'expiryBlock'), currentBlock: g('current_block', 'currentBlock'),
    recipient: g('recipient'), conditionRecipient: g('condition_recipient', 'conditionRecipient'),
    maxTransfer: g('max_transfer', 'maxTransfer'), registeredVkHash: g('registered_vk', 'registeredVk', 'registered_vk_hash'),
    proofVkHash: g('proof_vk', 'proofVk', 'proof_vk_hash'), taskId: g('task_id_field', 'taskIdField') ?? taskId,
  };
  const out = {};
  for (const [k, v] of Object.entries(m)) { const f = fe(v); if (f === null) return null; out[k] = f.toString(); }
  out.salt = (BigInt('0x' + crypto.randomBytes(31).toString('hex')) % P).toString();
  out.decision = decision === 'APPROVE' ? '1' : '0';
  return out;
}

// Returns { decision, proof, public_signals } for whichever decision the circuit accepts, or null.
async function prove(input, taskId, preferred) {
  const order = preferred === 'APPROVE' ? ['APPROVE', 'REJECT'] : ['REJECT', 'APPROVE'];
  for (const d of order) {
    const inp = inputsFor(input, taskId, d); if (!inp) return null;
    try { const { proof, publicSignals } = await lazy().groth16.fullProve(inp, WASM, ZKEY); return { decision: d, proof, public_signals: publicSignals }; }
    catch { /* circuit refused this decision */ }
  }
  return null;
}
module.exports = { prove, fe };
