// Steal the VFY turn handler (protocol v1). Schema-exact responses, deterministic strategy.
// EXTRACT is free and FORTIFY costs 2 to block 6, so EXTRACT 10 is the dominant move each turn
// (even vs a fortified opponent it still nets +4, versus -2 for FORTIFY and 0 for HOLD).
const crypto = require('crypto');
let keccak; try { keccak = require('js-sha3').keccak256; } catch { keccak = null; }
const pad = n => BigInt(n).toString(16).padStart(64, '0');
const ACT = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

function strings(o, out = [], d = 0) {
  if (d > 4 || o == null) return out;
  if (typeof o === 'string') { if (o.length > 12 && /\s/.test(o)) out.push(o); return out; }
  if (typeof o === 'object') for (const v of Object.values(o)) strings(v, out, d + 1);
  return out;
}
function chooseAction(env) {
  // Follow an explicit scenario brief when the turn carries one ("Decide whether to fortify ...").
  const brief = strings(env).join(' ');
  const m = brief.match(/decide whether to (fortify|hold|extract)/i) || brief.match(/\b(fortify|hold|extract)\b/i);
  const s = env.state || {};
  const turn = Number(env.turn || 0);
  const oppFort = s.opponentFortifiedUntilTurn != null && Number(s.opponentFortifiedUntilTurn) >= turn;
  if (m) {
    const k = m[1].toUpperCase();
    if (k === 'FORTIFY') return { type: 'FORTIFY' };
    if (k === 'HOLD') return { type: 'HOLD' };
  }
  if (oppFort && Number(s.selfBalance ?? 0) > Number(s.opponentBalance ?? 0)) return { type: 'HOLD' };
  const self = Number(s.selfBalance ?? 100), opp = Number(s.opponentBalance ?? 100);
  if (!(opp > 0)) return { type: 'HOLD' };            // nothing left to take
  return { type: 'EXTRACT', amount: Math.max(1, Math.min(10, Math.floor(opp))) };
}

function inputsHash(env, action) {
  if (!keccak) return undefined;
  try {
    const hex = [
      pad(BigInt(env.strategyCommitment?.hash ?? 0)),
      pad(BigInt('0x' + String(env.matchId).replace(/-/g, ''))),
      pad(env.turn), pad(env.state?.selfBalance ?? 0), pad(env.state?.opponentBalance ?? 0),
      pad(ACT[action.type]), pad(action.amount ?? 0), pad(1),
    ].join('');
    return '0x' + keccak(Buffer.from(hex, 'hex'));
  } catch { return undefined; }
}

// Deterministic RFC 4122 v4-format UUID, so a retried turn reuses the same key.
function uuidFrom(seed) {
  const b = crypto.createHash('sha256').update(seed).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
function respond(env) {
  const action = chooseAction(env);
  const policyProof = { circuitVersion: 'v1' };
  const h = inputsHash(env, action); if (h) policyProof.publicInputsHash = h;
  const out = {
    matchId: String(env.matchId),
    turn: Number(env.turn),
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: uuidFrom(`${env.matchId}:${env.turn}:${env.nonce || ''}`),
  };
  console.log(JSON.stringify({ ev: 'vfy', match: env.matchId, turn: env.turn, mode: env.mode, state: env.state, action }));
  return out;
}
module.exports = { respond, chooseAction, inputsHash };
