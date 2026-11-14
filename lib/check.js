// Offer Check: deterministic risk engine for "earn", airdrop, free-mint and task-app links.
// The model never decides the verdict. Rules score the evidence; an optional LLM only explains it.
const crypto = require('crypto');

const UA = 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Mobile Safari/537.36 OfferCheck/1.0';
const BRANDS = ['opensea', 'metamask', 'uniswap', 'binance', 'bybit', 'phantom', 'coinbase', 'trustwallet', 'okx', 'kucoin',
  'blur', 'magiceden', 'pancakeswap', 'rockstargames', 'playstation', 'zkverify', 'arbitrum', 'optimism', 'base', 'solana',
  'jupiter', 'raydium', 'layerzero', 'eigenlayer', 'hyperliquid', 'ledger', 'trezor', 'rabby', 'paypal', 'opay', 'palmpay', 'moniepoint',
  'roblox', 'shopee', 'steam', 'netflix', 'apple', 'icloud', 'microsoft', 'outlook', 'office365', 'amazon', 'facebook', 'instagram', 'whatsapp', 'dhl', 'usps', 'fedex', 'chase', 'wellsfargo', 'docusign'];
const OFFICIAL = new Set(['opensea.io', 'metamask.io', 'uniswap.org', 'app.uniswap.org', 'binance.com', 'bybit.com', 'phantom.app', 'phantom.com',
  'coinbase.com', 'trustwallet.com', 'okx.com', 'kucoin.com', 'blur.io', 'magiceden.io', 'pancakeswap.finance', 'rockstargames.com',
  'playstation.com', 'zkverify.io', 'arbitrum.io', 'optimism.io', 'base.org', 'solana.com', 'jup.ag', 'raydium.io', 'layerzero.network',
  'eigenlayer.xyz', 'hyperliquid.xyz', 'ledger.com', 'trezor.io', 'rabby.io', 'paypal.com', 'opayweb.com', 'palmpay.com', 'moniepoint.com',
  'roblox.com', 'shopee.com', 'steampowered.com', 'steamcommunity.com', 'netflix.com', 'apple.com', 'icloud.com', 'microsoft.com', 'outlook.com', 'live.com', 'office.com', 'amazon.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'dhl.com', 'usps.com', 'fedex.com', 'chase.com', 'wellsfargo.com', 'docusign.com', 'docusign.net',
  'x.com', 'twitter.com', 'github.com', 'google.com', 'youtube.com', 't.me', 'telegram.org', 'discord.com', 'discord.gg']);
const RISKY_TLDS = ['xyz', 'top', 'click', 'live', 'buzz', 'icu', 'shop', 'site', 'online', 'store', 'rest', 'cfd', 'sbs', 'lol', 'monster', 'vip', 'cc', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'claims', 'gift'];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'cutt.ly', 'is.gd', 'rb.gy', 't.ly', 'shorturl.at', 'ow.ly', 'rebrand.ly', 'tiny.cc'];

// Page patterns. weight: how much each adds to risk (0-100 scale overall).
const PATTERNS = [
  { id: 'SEED_PHRASE_REQUEST', w: 60, re: /(seed|recovery|secret|mnemonic)\s*(phrase|words)|12[- ]word|24[- ]word|enter your private key|import (your )?wallet/i, msg: 'Asks for a seed phrase or private key. No real project ever does this.' },
  { id: 'BLIND_SIGNING', w: 45, re: /eth_sign\b|setApprovalForAll|increaseAllowance|signTypedData(_v4)?|\bpermit2?\b\s*\(|approve\(\s*[^,]+,\s*(ethers\.constants\.MaxUint256|0xf{16,}|115792089237316195423570985008687907853269984665640564039457584007913129639935)/i, msg: 'Page code requests token approvals or blind signatures, the method wallet drainers use.' },
  { id: 'DRAINER_KIT', w: 60, re: /inferno ?drainer|angel ?drainer|pink ?drainer|venom ?drainer|ace ?drainer|monkey ?drainer|chick ?drainer|drainer\.js|seaport.*fulfillBasicOrder.*claim/i, msg: 'Contains code signatures of a known wallet-drainer kit.' },
  { id: 'OBFUSCATED_JS', w: 20, re: /eval\(\s*atob\(|eval\(function\(p,a,c,k,e,|_0x[0-9a-f]{4,}\s*=\s*\[|document\.write\(unescape\(/i, msg: 'Heavily obfuscated script, common in phishing kits.' },
  { id: 'CONNECT_TO_CLAIM', w: 25, re: /(connect (your )?wallet|wallet ?connect|web3modal|reown).{0,400}(claim|airdrop|reward|eligib|mint now|free mint)|(claim|airdrop|eligib).{0,400}(connect (your )?wallet|web3modal|walletconnect)/is, msg: 'Asks you to connect a wallet to claim a reward.' },
  { id: 'PAY_TO_UNLOCK', w: 40, re: /(pay|deposit|send).{0,40}(to (unlock|activate|withdraw|verify|claim))|activation fee|unlock (your )?(withdrawal|earnings|balance)|withdrawal fee.{0,40}before|registration fee|upgrade (your )?(account|level|vip).{0,40}(to withdraw|earn more)/i, msg: 'Wants a payment or deposit before you can withdraw or claim. Classic task-app scam.' },
  { id: 'GUARANTEED_RETURNS', w: 30, re: /guaranteed (daily |weekly )?(profit|income|returns?)|(\d{1,3})%\s*(daily|per day|every day)|double your (money|crypto|btc|eth)|risk[- ]free (profit|returns?)|earn \$?\d+[k]?\s*(daily|per day) (with|from) (no|zero)/i, msg: 'Promises guaranteed or very high daily returns.' },
  { id: 'TASK_APP_PONZI', w: 25, re: /(vip ?\d|level ?\d).{0,80}(commission|daily income|tasks? per day)|recharge.{0,40}(task|vip|level)|order grabbing|grab (the )?order|like (videos|posts) (and|to) earn.{0,60}(deposit|recharge)/i, msg: 'Looks like a "do tasks, recharge for VIP levels" scheme. These collapse and keep deposits.' },
  { id: 'FAKE_GIVEAWAY', w: 30, re: /(send|transfer) .{0,20}(btc|eth|sol|usdt|usdc).{0,60}(get|receive) .{0,10}(back|double|2x|x2)|free (gta ?(vi|6)|ps5|v-?bucks|robux) (code|key)s? generator|code generator/i, msg: 'Fake giveaway or "free code generator" pattern.' },
  { id: 'URGENCY', w: 8, re: /(only|last) \d+ (spots?|slots?|hours?|minutes?) left|offer ends in|hurry[,!]|limited time only|before it'?s too late/i, msg: 'Pressure tactics: fake countdowns or limited slots.' },
  { id: 'OFF_PLATFORM_CONTACT', w: 8, re: /(contact|message|dm|chat with) (our |the )?(admin|support|agent|manager) on (whatsapp|telegram)|wa\.me\/\d{8,}/i, msg: 'Pushes you to a private WhatsApp or Telegram "admin".' },
];

function levenshtein(a, b) {
  const m = a.length, n = b.length; if (!m) return n; if (!n) return m;
  const d = Array.from({ length: m + 1 }, (_, i) => [i]);
  for (let j = 1; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return d[m][n];
}
const registrable = h => { const p = h.split('.'); return p.length <= 2 ? h : (/^(co|com|org|net|gov|edu)\.[a-z]{2}$/.test(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.')); };

let phishCache = null, phishAt = 0;
async function phishingList() {
  if (phishCache && Date.now() - phishAt < 6 * 3600e3) return phishCache;
  try {
    const r = await fetch('https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json', { signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    phishCache = { black: new Set(j.blacklist), white: new Set(j.whitelist) }; phishAt = Date.now();
  } catch { phishCache = phishCache || null; }
  return phishCache;
}

// Second live feed: OpenPhish community list (refreshed ~12h), matched on exact host.
let opCache = null, opAt = 0;
async function openPhish() {
  if (opCache && Date.now() - opAt < 3 * 3600e3) return opCache;
  try {
    const r = await fetch('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt', { signal: AbortSignal.timeout(6000) });
    const set = new Set(); for (const line of (await r.text()).split('\n')) { try { set.add(new URL(line.trim()).hostname.toLowerCase().replace(/^www\./, '')); } catch {} }
    if (set.size) { opCache = set; opAt = Date.now(); }
  } catch {}
  return opCache;
}
const FREE_HOSTS = ['blogspot.com', 'weeblysite.com', 'weebly.com', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'github.io', 'web.app', 'firebaseapp.com', 'wixsite.com', 'glitch.me', 'square.site', 'webflow.io', 'framer.app', 'godaddysites.com', 'mystrikingly.com', 'ipfs.io', 'r2.dev', 'herokuapp.com', 'onrender.com', 'replit.app', 'sites.google.com'];

let rdapBoot = null;
async function rdapBase(tld) {
  if (!rdapBoot) {
    try { const j = await (await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(5000) })).json();
      rdapBoot = {}; for (const [tlds, urls] of j.services) for (const t of tlds) rdapBoot[t] = urls[0]; } catch { rdapBoot = null; return null; }
  }
  return rdapBoot[tld] || null;
}
async function domainAgeDays(domain) {
  try {
    const base = await rdapBase(domain.split('.').pop());
    const r = await fetch((base ? base.replace(/\/?$/, '/') : 'https://rdap.org/') + 'domain/' + domain, { signal: AbortSignal.timeout(6000), redirect: 'follow', headers: { accept: 'application/rdap+json, application/json', 'user-agent': UA } });
    if (!r.ok) return null;
    const j = await r.json();
    const ev = (j.events || []).find(e => e.eventAction === 'registration');
    return ev ? Math.floor((Date.now() - Date.parse(ev.eventDate)) / 864e5) : null;
  } catch { return null; }
}

async function fetchPage(url) {
  const chain = [];
  let cur = url, res = null;
  for (let i = 0; i < 6; i++) {
    try {
      res = await fetch(cur, { redirect: 'manual', headers: { 'user-agent': UA, accept: 'text/html,*/*' }, signal: AbortSignal.timeout(8000) });
    } catch (e) { return { ok: false, chain, error: String(e.message || e) }; }
    chain.push({ url: cur, status: res.status });
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) { cur = new URL(loc, cur).toString(); continue; }
    break;
  }
  let html = '';
  try { const buf = await res.arrayBuffer(); html = Buffer.from(buf).subarray(0, 1_500_000).toString('utf8'); } catch {}
  // Pull first-party scripts (up to 4) so drainer code loaded from JS files is seen too.
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map(m => { try { return new URL(m[1], cur).toString(); } catch { return null; } })
    .filter(Boolean).filter(s => new URL(s).hostname === new URL(cur).hostname).slice(0, 4);
  let js = '';
  await Promise.all(scripts.map(async s => { try { const r = await fetch(s, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(5000) }); js += '\n' + (await r.text()).slice(0, 800_000); } catch {} }));
  const title = (html.match(/<title[^>]*>([^<]{0,200})/i) || [])[1] || '';
  return { ok: true, finalUrl: cur, status: res.status, chain, html, js, title: title.trim() };
}

async function explain(report) {
  const key = process.env.GEMINI_API_KEY; if (!key) return null;
  try {
    const prompt = `You explain link-safety reports to everyday users in Nigeria. In 2 short plain sentences, say what this verdict means and what the user should do. Do not change the verdict.\n${JSON.stringify({ verdict: report.verdict, score: report.score, host: report.host, findings: report.findings.map(f => f.message) })}`;
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(8000),
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }) });
    const j = await r.json();
    return j.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || null;
  } catch { return null; }
}

async function check(input) {
  const started = Date.now();
  const findings = [];
  const add = (id, w, message, evidence) => findings.push({ id, weight: w, message, ...(evidence ? { evidence } : {}) });
  let url;
  try { url = new URL(/^https?:\/\//i.test(input) ? input : 'https://' + input); } catch { return { error: 'INVALID_URL' }; }
  if (!/^https?:$/.test(url.protocol)) return { error: 'UNSUPPORTED_SCHEME' };
  const host = url.hostname.toLowerCase().replace(/^www\./, '');
  const root = registrable(host);

  // 1. URL-level checks
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add('RAW_IP', 25, 'Link is a bare IP address instead of a domain.');
  if (host.includes('xn--')) add('PUNYCODE', 35, 'Domain uses look-alike (punycode) characters.', host);
  if (url.protocol === 'http:') add('NO_HTTPS', 10, 'Not served over HTTPS.');
  if (SHORTENERS.includes(host)) add('SHORTENER', 10, 'Link shortener hides the real destination.');
  const tld = root.split('.').pop();
  if (RISKY_TLDS.includes(tld)) add('RISKY_TLD', 8, `.${tld} domains are cheap and common in scams. Not proof on its own.`);
  if (url.searchParams.toString().match(/(ref|referral|invite|aff)=/i)) add('REFERRAL_LINK', 0, 'Contains a referral code, so whoever shared it earns from your signup.');

  const isOfficial = OFFICIAL.has(host) || OFFICIAL.has(root);
  const freeHost = FREE_HOSTS.find(f => host === f || host.endsWith('.' + f));
  if (freeHost && host !== freeHost) {
    const sub = host.slice(0, -(freeHost.length + 1));
    add('FREE_HOSTING', 15, `Hosted on a free site builder (${freeHost}), where scam pages are quick to spin up.`, host);
    const b = BRANDS.find(b => b.length >= 3 && sub.split(/[-.\d]/).some(w => w === b || (b.length >= 5 && w.includes(b))) || (b.length >= 5 && sub.includes(b)));
    if (b) add('BRAND_IMPERSONATION', 40, `Free-hosted page uses the "${b}" name but isn't its official site.`, host);
    if (sub.length >= 25 && /\d/.test(sub) && (sub.match(/-/g) || []).length >= 3) add('RANDOM_SUBDOMAIN', 25, 'Long machine-generated subdomain, typical of throwaway phishing pages.', host);
    if (/(mail|login|signin|verify|secure|account|wallet|claim|undian|hadiah|giveaway|support)/.test(sub)) add('LURE_WORDS', 15, 'Subdomain uses login, prize or account-verification bait words.', host);
  }
  if (!isOfficial && !freeHost) {
    const lbl = root.split('.')[0];
    if (BRANDS.includes(lbl) && lbl.length >= 4) add('LOOKALIKE_TLD', 35, `Uses the "${lbl}" name on a different domain ending than the real site.`, root);
  }
  if (!isOfficial && !freeHost) {
    const rawLabel = host.split('.').slice(0, -1).join('-');
    const label = root.split('.')[0].replace(/-/g, '');
    const parts = [label, ...rawLabel.split(/[-.]/).filter(x => x.length >= 4)];
    const near = (w, b) => { if (w.length < b.length - 1) return false; for (let i = 0; i + b.length - 1 <= w.length; i++) for (const L of [b.length - 1, b.length, b.length + 1]) { const seg = w.slice(i, i + L); if (seg.length === L && seg !== b && levenshtein(seg, b) <= (b.length >= 7 ? 2 : 1)) return true; } return false; };
    for (const b of BRANDS) {
      if (label === b) continue;
      if (b.length >= 5 && parts.some(w => near(w, b)) || (b.length >= 5 && parts.some(w => w.includes(b) && w !== b)) || (b.length === 4 && parts.some(w => w.includes(b) && w !== b && /claim|airdrop|reward|gift|bonus|verify|wallet|mint|support/.test(w)))) {
        add('BRAND_IMPERSONATION', 40, `Domain imitates "${b}" but isn't its official site.`, root); break;
      }
    }
  }

  // 2. Threat intel + domain age (parallel with page fetch)
  const [phish, age, page, op] = await Promise.all([phishingList(), domainAgeDays(root), fetchPage(url.toString()), openPhish()]);
  if (op && (op.has(host) || (!freeHost && op.has(root)))) add('KNOWN_PHISHING', 90, 'Listed as an active phishing site on the OpenPhish feed.', host);
  if (phish) {
    if (phish.black.has(host) || phish.black.has(root)) add('KNOWN_PHISHING', 90, 'Listed as a phishing site on MetaMask\'s public blocklist.', root);
  }
  if (age !== null) {
    if (age < 14) add('NEW_DOMAIN', 30, `Domain registered only ${age} days ago.`);
    else if (age < 60) add('YOUNG_DOMAIN', 15, `Domain is only ${age} days old.`);
  }

  // 3. Page content
  let snapshotHash = null, finalHost = host;
  if (!page.ok) add('UNREACHABLE', 5, 'Could not load the page, so its content wasn\'t checked.');
  else {
    finalHost = new URL(page.finalUrl).hostname.replace(/^www\./, '');
    if (registrable(finalHost) !== root) add('REDIRECTS_ELSEWHERE', 15, `Redirects to a different site: ${finalHost}`);
    if (phish && (phish.black.has(finalHost) || phish.black.has(registrable(finalHost)))) add('KNOWN_PHISHING', 90, 'Redirect target is on MetaMask\'s phishing blocklist.', finalHost);
    const text = page.html + '\n' + page.js;
    for (const p of PATTERNS) {
      const m = text.match(p.re);
      const CODE = ['BLIND_SIGNING', 'DRAINER_KIT', 'OBFUSCATED_JS'];
      if (m && !CODE.includes(p.id)) {
        // Ignore anti-scam warnings like "never pay a fee to unlock" or "if anyone asks for your seed phrase".
        const before = text.slice(Math.max(0, m.index - 80), m.index).toLowerCase();
        const after = text.slice(m.index + m[0].length, m.index + m[0].length + 120).toLowerCase();
        if (/(never|don'?t|do not|won'?t|will not|no one|nobody|no real|no legit|if anyone|beware|scam|warning|avoid|not ask|never ask)[^.!?]*$/.test(before)) continue;
        if (/^[^.!?]*[.!?]?[^.!?]*(is a scam|are scams|it'?s a scam|report (it|them)|red flag)/.test(after)) continue;
      }
      if (m && !(isOfficial && ['CONNECT_TO_CLAIM', 'BLIND_SIGNING', 'URGENCY'].includes(p.id))) add(p.id, p.w, p.msg, m[0].slice(0, 80));
    }
    snapshotHash = '0x' + crypto.createHash('sha256').update(page.html).digest('hex');
  }

  // 4. Score -> verdict (deterministic)
  const seen = new Set();
  const uniq = findings.filter(f => !seen.has(f.id) && seen.add(f.id));
  let score = Math.min(100, uniq.reduce((s, f) => s + f.weight, 0));
  if (isOfficial && !uniq.some(f => f.id === 'KNOWN_PHISHING')) score = Math.min(score, 15);
  const critical = uniq.some(f => ['KNOWN_PHISHING', 'SEED_PHRASE_REQUEST', 'DRAINER_KIT'].includes(f.id));
  const verdict = critical || score >= 60 ? 'DANGER' : score >= 25 ? 'CAUTION' : 'LOOKS_OK';
  const advice = {
    DANGER: 'Do not connect a wallet, sign, pay, or enter any details here.',
    CAUTION: 'Be careful. Use a fresh burner wallet, never pay a fee to unlock earnings, and verify on the project\'s official X account.',
    LOOKS_OK: 'No red flags found. That is not a guarantee, so still never share a seed phrase or pay to unlock earnings.',
  }[verdict];

  const report = {
    url: url.toString(), host, final_url: page.finalUrl || null, title: page.title || null,
    verdict, score, advice, findings: uniq.sort((a, b) => b.weight - a.weight),
    domain_age_days: age, redirect_chain: page.chain || [],
    evidence: { page_sha256: snapshotHash, checked_at: new Date().toISOString(), engine: 'offer-check/1.0', blocklist: phish ? 'MetaMask eth-phishing-detect' : 'unavailable' },
    ms: Date.now() - started,
  };
  report.evidence.report_commitment = '0x' + crypto.createHash('sha256').update(JSON.stringify({ u: report.url, v: verdict, s: score, f: report.findings.map(f => f.id), p: snapshotHash, t: report.evidence.checked_at })).digest('hex');
  report.explanation = await explain(report);
  return report;
}

module.exports = { check };
