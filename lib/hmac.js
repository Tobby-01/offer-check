// HMAC-SHA256 signing for the zkVerify Agent Games protocol.
// The platform signs the RAW request body and sends it in x-agent-games-signature.
// Undocumented details handled defensively: key may be hex text or decoded bytes,
// header may be bare hex or "sha256=<hex>". We mirror the form that verified.
const crypto = require('crypto');

function parseSig(v) {
  const raw = typeof v === 'string' ? v.trim() : '';
  const m = raw.match(/^([A-Za-z0-9_.-]+)=([0-9a-fA-F]+)$/);
  return m ? { prefix: m[1] + '=', digest: m[2].toLowerCase() } : { prefix: '', digest: raw.toLowerCase() };
}
function keyForms(secret) {
  const s = String(secret || '').trim();
  const forms = [{ form: 'text', key: Buffer.from(s, 'utf8') }];
  const hex = s.replace(/^0x/i, '');
  if (hex && hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex)) forms.push({ form: 'hex', key: Buffer.from(hex, 'hex') });
  return forms;
}
const hmacHex = (key, body) => crypto.createHmac('sha256', key).update(body).digest('hex');
function safeEq(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function secrets() {
  return [...new Set([...(process.env.AGENT_GAMES_HMAC_SECRETS || '').split(','), process.env.AGENT_GAMES_HMAC_SECRET || '']
    .map(s => s.trim()).filter(Boolean))];
}
function verify(rawBody, header) {
  const { prefix, digest } = parseSig(header);
  if (!digest) return { ok: false };
  for (const secret of secrets()) for (const { form, key } of keyForms(secret)) {
    if (safeEq(hmacHex(key, rawBody), digest)) return { ok: true, secret, keyForm: form, prefix };
  }
  return { ok: false };
}
function sign(secret, body, { keyForm = 'text', prefix = '' } = {}) {
  const f = keyForms(secret).find(x => x.form === keyForm) || keyForms(secret)[0];
  return prefix + hmacHex(f.key, body);
}
module.exports = { verify, sign, secrets };
