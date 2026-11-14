// Proof Gatekeeper policy (zkVerify Agent Games). Deterministic, fails closed.
// Scoring: +12 correct, -6 approving a trap, -3 rejecting a valid request,
// so anything missing or unparseable is a REJECT.
const seen = new Map(); // proof_tx -> task_id (per warm instance)
const pick = (o, ks) => { for (const k of ks) if (o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k]; };
const hex = v => typeof v === 'string' ? v.trim().toLowerCase().replace(/^0x/, '') : '';
const big = v => { if (typeof v === 'bigint') return v; if (typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
  if (typeof v === 'string' && /^(0x[0-9a-f]+|\d+)$/i.test(v.trim())) return BigInt(v.trim()); return null; };
const KNOWN_VKS = ['6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0', '6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047'];

function decide(input, taskId) {
  const no = code => ({ decision: 'REJECT', reason_code: code });
  if (!input || typeof input !== 'object') return no('PROOF_INVALID');
  const proofTx = hex(pick(input, ['proof_tx', 'proofTx']));
  // 1. replay: a proof reference may back only one task
  if (proofTx && seen.has(proofTx) && seen.get(proofTx) !== taskId) return no('PROOF_REPLAY');
  // 2. verification key substitution / wrong circuit
  const reg = hex(pick(input, ['registered_vk', 'registeredVk', 'vk_hash'])), pvk = hex(pick(input, ['proof_vk', 'proofVk']));
  if (!reg || !pvk) return no('PROOF_INVALID');
  if (reg !== pvk) return no(KNOWN_VKS.includes(pvk) ? 'CIRCUIT_MISMATCH' : 'VK_SUBSTITUTION');
  // 3. needs an on-chain verification reference
  if (!proofTx) return no('MISSING_VERIFICATION');
  if (input.verified === false || input.verification_status && !/final/i.test(String(input.verification_status))) return no('MISSING_VERIFICATION');
  // 4. threshold
  const min = big(pick(input, ['minimum', 'min_threshold'])), bal = big(pick(input, ['public_balance', 'publicBalance']));
  if (min === null || bal === null) return no('PUBLIC_INPUT_MISMATCH');
  if (bal < min) return no('THRESHOLD_MISMATCH');
  // 5. expiry
  const exp = big(pick(input, ['expiry_block', 'expiryBlock'])), cur = big(pick(input, ['current_block', 'currentBlock']));
  if (exp === null || cur === null || cur >= exp) return no('PUBLIC_INPUT_MISMATCH');
  // 6. recipient, exact
  const r = hex(pick(input, ['recipient'])), cr = hex(pick(input, ['condition_recipient', 'conditionRecipient']));
  if (!r || !cr || r !== cr) return no('PUBLIC_INPUT_MISMATCH');
  // 7. amount within cap
  const amt = big(pick(input, ['amount'])), cap = big(pick(input, ['max_transfer', 'maxTransfer']));
  if (amt === null || cap === null || amt <= 0n || amt > cap) return no('PUBLIC_INPUT_MISMATCH');
  return { decision: 'APPROVE', reason_code: 'VALID_PROOF' };
}

const { prove } = require('./prover');
// Checks the circuit cannot see (replay, missing on-chain verification) always win.
const OFF_CIRCUIT = new Set(['PROOF_REPLAY', 'MISSING_VERIFICATION', 'PROOF_INVALID']);
async function respond(task) {
  const input = task.input || {};
  let d = decide(input, task.task_id);
  const out = { task_id: task.task_id };
  let p = null;
  try { p = await Promise.race([prove(input, task.task_id, d.decision), new Promise(r => setTimeout(() => r(null), 40000))]); } catch {}
  if (p && p.decision !== d.decision && !OFF_CIRCUIT.has(d.reason_code)) {
    // the circuit is the referee: follow it (it only proves the rule-correct decision)
    d = p.decision === 'APPROVE' ? { decision: 'APPROVE', reason_code: 'VALID_PROOF' } : { decision: 'REJECT', reason_code: d.reason_code === 'VALID_PROOF' ? 'PUBLIC_INPUT_MISMATCH' : d.reason_code };
  }
  if (d.decision === 'APPROVE') { const tx = hex(pick(input, ['proof_tx', 'proofTx'])); if (tx) seen.set(tx, task.task_id); }
  Object.assign(out, d);
  const tx = pick(input, ['proof_tx', 'proofTx']); if (tx) out.proof_tx = tx;
  if (p && p.decision === d.decision) { out.proof = p.proof; out.public_signals = p.public_signals; }
  console.log(JSON.stringify({ ev: 'gk', task: task.task_id, mode: task.mode, keys: Object.keys(input), decision: d.decision, reason: d.reason_code, proved: !!out.proof }));
  return out;
}
module.exports = { decide, respond };
