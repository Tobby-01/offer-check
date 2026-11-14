// Steal the VFY turn handler (protocol v1). Schema-exact responses, deterministic strategy.
// EXTRACT is free and FORTIFY costs 2 to block 6, so EXTRACT 10 is the dominant move each turn
// (even vs a fortified opponent it still nets +4, versus -2 for FORTIFY and 0 for HOLD).
const crypto = require('crypto');
let keccak; try { keccak = require('js-sha3').keccak256; } catch { keccak = null; }
const pad = n => BigInt(n).toString(16).padStart(64, '0');
const ACT = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

function chooseAction(env) {
  const s = env.state || {};
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
    idempotencyKey: crypto.createHash('sha256').update(`${env.matchId}:${env.turn}:${env.nonce || ''}`).digest('hex').slice(0, 32),
  };
  console.log(JSON.stringify({ ev: 'vfy', match: env.matchId, turn: env.turn, mode: env.mode, state: env.state, action }));
  return out;
}
module.exports = { respond, chooseAction, inputsHash };
