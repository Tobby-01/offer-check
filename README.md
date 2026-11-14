# Offer Check

**Paste any airdrop, free-mint, task-app or "free code" link and find out if it's a scam before you connect a wallet or pay.**

Built for the zkVerify Agent Games 2026 (Wildcard track) by Pixxel ([@King_pixxel](https://x.com/King_pixxel)).

## The problem
In Nigeria and across emerging markets, people looking for online income get a constant stream of links: "free" mints, airdrop claims, task apps that pay you to like posts, free GTA 6 or PS5 code sites. Many of them are wallet drainers or pay-to-unlock schemes. One wrong click can empty a wallet, or a "withdrawal fee" can take savings people can't afford to lose. Existing tools are made for crypto natives and say nothing about task-app scams.

## What the agent does
1. **URL checks:** raw IPs, punycode look-alikes, link shorteners, cheap TLDs, referral codes, and look-alike spellings of 30+ brands (OpenSea, MetaMask, Binance, Phantom, OPay, PalmPay, Rockstar and more).
2. **Threat intel:** MetaMask's public `eth-phishing-detect` blocklist, plus domain age from RDAP via the IANA bootstrap.
3. **Live page scan:** follows redirects, then reads the HTML and same-site scripts for seed-phrase prompts, blind signing and approvals (`eth_sign`, `setApprovalForAll`, `permit`, unlimited `approve`), known drainer kits, obfuscated JS, connect-to-claim flows, pay-to-unlock and recharge-for-VIP task schemes, guaranteed-profit promises and fake giveaways.
4. **False-positive guard:** anti-scam warnings on honest sites ("if anyone asks you for a fee to unlock, it's a scam") are recognised and ignored.
5. **Deterministic verdict:** rules produce `LOOKS_OK`, `CAUTION` or `DANGER` with a 0 to 100 score and evidence. An LLM (Gemini, optional) only rewrites the advice in plain words and can never change the verdict.
6. **Verifiable evidence:** each report carries the SHA-256 of the exact page snapshot and a commitment over (url, verdict, score, findings, snapshot, time). Anyone can check later what the agent based its answer on.

## Endpoints
- `GET /api/check?url=<link>`: public JSON report, also used by the web UI.
- `POST /agent`: zkVerify Agent Games endpoint. Verifies HMAC-SHA256 of the raw body (`x-agent-games-signature`), answers preflight with `{ ok: true, protocolVersion: "v1" }`, signs every response, and **fails closed**: on a timeout or error the answer is REJECT.

## Env
- `AGENT_GAMES_HMAC_SECRET`: from Rotate Secret on the Agent Games dashboard.
- `GEMINI_API_KEY` (optional): plain-language explanations.

## Limits
A clean result is not a guarantee. The scanner sees what the page serves to it, and some drainers cloak themselves from bots. It never connects a wallet, signs, or submits anything.

## Roadmap
- Anchor the report commitment on zkVerify (Groth16 proof that verdict = rules(findings)) so the verdict is checkable on-chain.
- Telegram and WhatsApp bot front-end, where most of these links are shared.
- On-chain checks of contract addresses found on the page (verified source, approval targets).
