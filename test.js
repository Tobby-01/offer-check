const { check } = require('./lib/check');
(async () => { for (const u of process.argv.slice(2)) { const r = await check(u); console.log(u, '=>', r.verdict, r.score, (r.findings||[]).map(f=>f.id).join(','), r.domain_age_days, r.ms+'ms'); } })();
