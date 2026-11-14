// zkVerify Agent Games endpoint. Verifies HMAC over the raw body, answers preflight,
// and runs Offer Check for any task that carries a URL. Fails closed.
const { verify, sign, secrets } = require('../lib/hmac');
const { check } = require('../lib/check');
const gatekeeper = require('../lib/gatekeeper');
const vfy = require('../lib/vfy');

const readRaw = req => new Promise((ok, no) => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => ok(Buffer.concat(c))); req.on('error', no); });
function findUrl(o, depth = 0) {
  if (!o || depth > 4) return null;
  if (typeof o === 'string') return /^https?:\/\/\S+$/i.test(o.trim()) ? o.trim() : null;
  if (typeof o !== 'object') return null;
  for (const k of ['url', 'link', 'target', 'offer_url', 'input']) { const v = findUrl(o[k], depth + 1); if (v) return v; }
  for (const v of Object.values(o)) { const u = findUrl(v, depth + 1); if (u) return u; }
  return null;
}

module.exports = async (req, res) => {
  if (req.method === 'GET' && String(req.url).includes('selftest')) {
    const t0 = Date.now();
    const r = await gatekeeper.respond({ task_id: 'selftest', mode: 'selftest', input: { registered_vk: '0x7d91', proof_vk: '0x7d91', minimum: '1000', public_balance: '900', expiry_block: 10, current_block: 5, recipient: '0xab', condition_recipient: '0xab', amount: '1', max_transfer: '2', proof_tx: '0x' + Date.now().toString(16) } });
    return res.status(200).json({ decision: r.decision, reason_code: r.reason_code, proved: !!r.proof, ms: Date.now() - t0 });
  }
  if (req.method === 'GET') return res.status(200).json({ ok: true, agent: 'offer-check', protocolVersion: 'v1', usage: 'POST signed tasks here. Public demo: /api/check?url=' });
  if (req.method !== 'POST') return res.status(405).end();
  const raw = await readRaw(req);
  const send = (status, obj, v) => {
    const body = Buffer.from(JSON.stringify(obj));
    if (v && v.ok) res.setHeader('x-agent-games-signature', sign(v.secret, body, v));
    res.setHeader('content-type', 'application/json');
    res.status(status).end(body);
  };
  if (!secrets().length) return send(503, { ok: false, error: 'AGENT_SECRET_NOT_CONFIGURED' });
  const v = verify(raw, req.headers['x-agent-games-signature']);
  if (!v.ok) return send(401, { ok: false, error: 'BAD_SIGNATURE' });
  let task; try { task = JSON.parse(raw.toString('utf8')); } catch { return send(400, { ok: false, error: 'BAD_JSON' }, v); }
  const type = String(task.type || '');
  if (type.includes('preflight')) return send(200, { ok: true, protocolVersion: 'v1' }, v);
  const ev = String(task.eventId || '');
  if (ev.includes('steal') || type.includes('steal') || (task.matchId && task.turn !== undefined)) {
    try { return send(200, vfy.respond(task), v); }
    catch { return send(200, { matchId: String(task.matchId), turn: Number(task.turn), action: { type: 'HOLD' }, policyProof: { circuitVersion: 'v1' }, agentTimestamp: new Date().toISOString(), idempotencyKey: require('crypto').randomUUID() }, v); }
  }
  if (type.includes('proof-gatekeeper') || ev.includes('gatekeeper')) { try { return send(200, await gatekeeper.respond(task), v); } catch { return send(200, { task_id: task.task_id, decision: 'REJECT', reason_code: 'PROOF_INVALID' }, v); } }
  const url = findUrl(task.input || task);
  if (!url) return send(200, { task_id: task.task_id, decision: 'REJECT', reason_code: 'NO_URL_IN_TASK', protocolVersion: 'v1' }, v);
  try {
    const r = await Promise.race([check(url), new Promise((_, no) => setTimeout(() => no(new Error('timeout')), 45000))]);
    return send(200, { task_id: task.task_id, decision: r.verdict === 'LOOKS_OK' ? 'APPROVE' : 'REJECT', reason_code: r.findings?.[0]?.id || 'NO_RED_FLAGS', verdict: r.verdict, score: r.score, findings: r.findings, evidence: r.evidence, protocolVersion: 'v1' }, v);
  } catch { return send(200, { task_id: task.task_id, decision: 'REJECT', reason_code: 'TIMEOUT_FAIL_CLOSED', protocolVersion: 'v1' }, v); }
};
