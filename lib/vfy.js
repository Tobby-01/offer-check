// Steal the VFY turn handler (protocol v1) with real Groth16 policy proofs (official vfy-policy circuit).
// Strategy params + salt come only from env (VFY_STRATEGY_PARAMS, VFY_STRATEGY_SALT, VFY_COMMITMENT); never commit them.
// Circuit inputs: strategyParams[8], salt, commitment = Poseidon(params, salt), matchId, turnNumber,
// selfBalance, opponentBalance, action (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount, circuitVersion (1).
// The circuit only accepts the action the committed params dictate, so we try the expected one first
// and fall back to the others: a proof exists for exactly one action.
const crypto = require('crypto');
const path = require('path');
let keccak; try { keccak = require('js-sha3').keccak256; } catch { keccak = null; }
let snarkjs; const lazy = () => (snarkjs ||= require('snarkjs'));
const WASM = path.join(__dirname, '..', 'circuits', 'vfy-policy.wasm');
const ZKEY = path.join(__dirname, '..', 'circuits', 'vfy-policy_final.zkey');
const pad = n => BigInt(n).toString(16).padStart(64, '0');
const ACT = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };
const CODE = ['HOLD', 'FORTIFY', 'EXTRACT'];

function strategy() {
  const p = String(process.env.VFY_STRATEGY_PARAMS || '').split(',').map(s => s.trim()).filter(Boolean);
  const salt = process.env.VFY_STRATEGY_SALT, commitment = process.env.VFY_COMMITMENT;
  if (p.length !== 8 || !salt || !commitment) return null;
  return { params: p.map(x => BigInt(x)), salt: BigInt(salt), commitment: BigInt(commitment) };
}
const int = v => { const n = Number(v); return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0; };

// Mirrors the circuit rule found by probing: FORTIFY if self < p1, else HOLD if opp <= p2, else EXTRACT p0.
function expected(st, self, opp) {
  const [p0, p1, p2] = st.params.map(Number);
  if (self < p1) return { type: 'FORTIFY' };
  if (opp <= p2) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: p0 };
}
function candidates(st, self, opp) {
  const first = expected(st, self, opp);
  const p0 = Number(st.params[0]);
  const all = [first, { type: 'EXTRACT', amount: p0 }, { type: 'HOLD' }, { type: 'FORTIFY' }];
  const seen = new Set(); return all.filter(a => { const k = a.type + (a.amount ?? ''); if (seen.has(k)) return false; seen.add(k); return true; });
}
function matchField(id) { return BigInt('0x' + String(id).replace(/[^0-9a-f]/gi, '') || '0'); }

function inputsHash(commitHex, env, action) {
  if (!keccak) return undefined;
  try {
    const hex = [
      pad(BigInt(commitHex)), pad(matchField(env.matchId)), pad(env.turn),
      pad(int(env.state?.selfBalance)), pad(int(env.state?.opponentBalance)),
      pad(ACT[action.type]), pad(action.amount ?? 0), pad(1),
    ].join('');
    return '0x' + keccak(Buffer.from(hex, 'hex'));
  } catch { return undefined; }
}

async function proveTurn(env) {
  const st = strategy(); if (!st) return null;
  const self = int(env.state?.selfBalance ?? 100), opp = int(env.state?.opponentBalance ?? 100);
  for (const action of candidates(st, self, opp)) {
    const inp = {
      strategyParams: st.params.map(String), salt: st.salt.toString(), commitment: st.commitment.toString(),
      matchId: matchField(env.matchId).toString(), turnNumber: String(int(env.turn)),
      selfBalance: String(self), opponentBalance: String(opp),
      action: ACT[action.type].toString(), amount: String(action.amount ?? 0), circuitVersion: '1',
    };
    try {
      const { proof, publicSignals } = await lazy().groth16.fullProve(inp, WASM, ZKEY);
      return { action, proof, publicSignals, commitHex: '0x' + st.commitment.toString(16).padStart(64, '0') };
    } catch { /* circuit refused this action */ }
  }
  return null;
}

// Deterministic RFC 4122 v4-format UUID, so a retried turn reuses the same key.
function uuidFrom(seed) {
  const b = crypto.createHash('sha256').update(seed).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

async function respond(env) {
  const t0 = Date.now();
  const r = await proveTurn(env);
  const action = r ? r.action : { type: 'HOLD' };
  const policyProof = { circuitVersion: 'v1' };
  if (r) {
    policyProof.proof = r.proof;
    policyProof.public_signals = r.publicSignals;
    const h = inputsHash(env.strategyCommitment?.hash || r.commitHex, env, action); if (h) policyProof.publicInputsHash = h;
  }
  const out = {
    matchId: String(env.matchId),
    turn: Number(env.turn),
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: uuidFrom(`${env.matchId}:${env.turn}:${env.nonce || ''}`),
  };
  console.log(JSON.stringify({ ev: 'vfy', match: env.matchId, turn: env.turn, mode: env.mode, state: env.state, action, proved: !!r, ms: Date.now() - t0 }));
  return out;
}
module.exports = { respond, proveTurn, inputsHash, expected };
