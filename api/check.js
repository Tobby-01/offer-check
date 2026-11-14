const { check } = require('../lib/check');
module.exports = async (req, res) => {
  res.setHeader('access-control-allow-origin', '*');
  if (req.method === 'OPTIONS') { res.setHeader('access-control-allow-headers', 'content-type'); return res.status(204).end(); }
  const url = req.method === 'POST' ? (req.body && req.body.url) : req.query.url;
  if (!url) return res.status(400).json({ error: 'Pass ?url=<link> or POST {"url": "..."}' });
  try { const r = await check(String(url).trim()); res.status(r.error ? 400 : 200).json(r); }
  catch (e) { res.status(500).json({ error: 'CHECK_FAILED' }); }
};
