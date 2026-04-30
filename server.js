/**
 * hive-prospector-qualifier
 *
 * Stand-alone Render service that gatekeeps Prospector's Bonanza admission.
 *
 * Doctrine (post-2026-04-25 hardening — no bypasses):
 *   1. Caller submits 3 candidate x402 transaction hashes (Base L2 USDC payments
 *      they made into the Hive treasury for paid Hive surface calls within the
 *      last WINDOW_DAYS days).
 *   2. Qualifier verifies each tx on-chain via Base RPC: Transfer event from
 *      caller-supplied `address` to HIVE_TREASURY_ADDRESS, USDC contract,
 *      timestamp inside the window, all three distinct.
 *   3. On pass: qualifier
 *        a. mints an HMAC qualification_token (shared secret with hivebank)
 *        b. mints an Ed25519-signed ZK ticket (its own key — compromise isolation)
 *        c. POSTs to hivebank /v1/bank/prospector/admit with x-hive-internal
 *      Returns the token + ticket to the caller, who then calls
 *      hivebank /v1/bank/prospector/claim with both.
 *   4. Replay protection: each tx_hash can only be used once across ALL admits;
 *      each (did, address) pair can only be admitted once.
 *
 * No mock rails. Verification is Base L2 RPC with USDC Transfer log parse.
 * If RPC is down, the request fails closed.
 */

const express = require('express');
const crypto = require('crypto');
const nacl = require('tweetnacl');

const app = express();
app.use(express.json({ limit: '64kb' }));

// ─── Config (fail closed on missing critical env) ─────────────────────────────
const PORT                       = parseInt(process.env.PORT || '10000', 10);
const QUALIFIER_DID              = process.env.QUALIFIER_DID || 'did:hive:prospector-qualifier-001';
const HIVEBANK_BASE_URL          = (process.env.HIVEBANK_BASE_URL || 'https://hivebank.onrender.com').replace(/\/$/, '');
const HIVE_TREASURY_ADDRESS      = (process.env.HIVE_TREASURY_ADDRESS || '0x15184bf50b3d3f52b60434f8942b7d52f2eb436e').toLowerCase();
const BASE_RPC_URL               = process.env.BASE_RPC_URL || 'https://1rpc.io/base';
const USDC_CONTRACT              = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'; // Base mainnet USDC
const TRANSFER_TOPIC             = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const WINDOW_DAYS                = parseInt(process.env.WINDOW_DAYS || '30', 10);
const MIN_PAID_CALLS             = parseInt(process.env.MIN_PAID_CALLS || '3', 10);
const TOKEN_TTL_SEC              = parseInt(process.env.TOKEN_TTL_SEC || '604800', 10);

const HMAC_SECRET                = process.env.PROSPECTOR_QUALIFIER_SECRET || '';
const HIVE_INTERNAL_KEY          = process.env.HIVE_INTERNAL_KEY || '';
const ED25519_SECRET_B64         = process.env.ZK_TICKET_ED25519_SECRET_B64 || '';
const ED25519_PUBLIC_B64         = process.env.ZK_TICKET_ED25519_PUBLIC_B64 || '';

function configErrors() {
  const errs = [];
  if (!HMAC_SECRET) errs.push('PROSPECTOR_QUALIFIER_SECRET');
  if (!HIVE_INTERNAL_KEY) errs.push('HIVE_INTERNAL_KEY');
  if (!ED25519_SECRET_B64) errs.push('ZK_TICKET_ED25519_SECRET_B64');
  if (!ED25519_PUBLIC_B64) errs.push('ZK_TICKET_ED25519_PUBLIC_B64');
  return errs;
}

// ─── Replay-protection store (in-memory; survives reboot via hivebank-side
// idempotency on jti, so this is best-effort fast-path defense) ───────────────
const usedTxHashes = new Set();
const admittedKeys = new Set(); // `${didLc}|${addrLc}`

// ─── Helpers ──────────────────────────────────────────────────────────────────
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function isHex(s, len) {
  return typeof s === 'string' && /^0x[0-9a-fA-F]+$/.test(s) && (len ? s.length === 2 + len : true);
}

function isAddress(s) {
  return isHex(s, 40);
}

function isTxHash(s) {
  return isHex(s, 64);
}

function timingSafeEqStr(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ─── On-chain verification ────────────────────────────────────────────────────
async function rpcCall(method, params) {
  const res = await fetch(BASE_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`rpc_http_${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(`rpc_${data.error.code || 'error'}: ${data.error.message || ''}`);
  return data.result;
}

/**
 * Verify one paid x402 call.
 * Required: tx is mined on Base, USDC Transfer from caller `address` to Hive
 * treasury, amount > 0, block timestamp inside WINDOW_DAYS window.
 *
 * Returns: { ok: true, amount_usdc, block_number, ts } or { ok: false, reason }
 */
async function verifyPaidCall({ txHash, fromAddress, windowStartUnix }) {
  const fromLc = fromAddress.toLowerCase();
  let receipt;
  try {
    receipt = await rpcCall('eth_getTransactionReceipt', [txHash]);
  } catch (e) {
    return { ok: false, reason: 'rpc_unavailable', detail: e.message };
  }
  if (!receipt) return { ok: false, reason: 'tx_not_found' };
  if (receipt.status !== '0x1') return { ok: false, reason: 'tx_failed_on_chain' };

  // Find USDC Transfer log from caller → treasury
  let amountUsdc = 0;
  let matched = false;
  for (const log of receipt.logs || []) {
    if (!log.address || log.address.toLowerCase() !== USDC_CONTRACT) continue;
    if (!log.topics || log.topics[0] !== TRANSFER_TOPIC) continue;
    if (!log.topics[1] || !log.topics[2]) continue;
    const sender    = '0x' + log.topics[1].slice(26).toLowerCase();
    const recipient = '0x' + log.topics[2].slice(26).toLowerCase();
    if (sender !== fromLc) continue;
    if (recipient !== HIVE_TREASURY_ADDRESS) continue;
    amountUsdc = parseInt(log.data, 16) / 1_000_000;
    if (amountUsdc <= 0) continue;
    matched = true;
    break;
  }
  if (!matched) return { ok: false, reason: 'no_matching_transfer', detail: `expected USDC Transfer from ${fromLc} to ${HIVE_TREASURY_ADDRESS}` };

  // Pull block timestamp to enforce WINDOW_DAYS
  let block;
  try {
    block = await rpcCall('eth_getBlockByNumber', [receipt.blockNumber, false]);
  } catch (e) {
    return { ok: false, reason: 'rpc_unavailable', detail: e.message };
  }
  if (!block || !block.timestamp) return { ok: false, reason: 'block_not_found' };
  const ts = parseInt(block.timestamp, 16);
  if (ts < windowStartUnix) return { ok: false, reason: 'outside_window', detail: `tx older than ${WINDOW_DAYS} days` };

  return {
    ok: true,
    amount_usdc: amountUsdc,
    block_number: parseInt(receipt.blockNumber, 16),
    ts,
  };
}

// ─── Token + ticket minting ───────────────────────────────────────────────────
function mintQualificationToken({ did, address, paidCalls, jti }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    typ: 'hive-prospector-qualification',
    v: 1,
    iss: QUALIFIER_DID,
    did,
    address: address.toLowerCase(),
    paid_calls: paidCalls,
    iat: now,
    exp: now + TOKEN_TTL_SEC,
    jti,
  };
  const body = b64url(JSON.stringify(payload));
  const sig  = crypto.createHmac('sha256', HMAC_SECRET).update(body).digest();
  return `${body}.${b64url(sig)}`;
}

function mintZkTicket({ did, address, jti }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    typ: 'hive-spectral-zk-ticket',
    v: 1,
    iss: QUALIFIER_DID,
    pubkey: ED25519_PUBLIC_B64,
    did,
    address: address.toLowerCase(),
    route: 'prospector',
    iat: now,
    exp: now + TOKEN_TTL_SEC,
    jti,
  };
  const body = b64url(JSON.stringify(payload));
  const secret = fromB64url(ED25519_SECRET_B64);
  if (secret.length !== 64) {
    throw new Error('ed25519_secret_invalid_length');
  }
  const sig = nacl.sign.detached(Buffer.from(body), secret);
  return `${body}.${b64url(sig)}`;
}

// ─── Hivebank admit call ──────────────────────────────────────────────────────
async function callHivebankAdmit({ did, address, qualificationToken }) {
  const url = `${HIVEBANK_BASE_URL}/v1/bank/prospector/admit`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-hive-internal': HIVE_INTERNAL_KEY,
    },
    body: JSON.stringify({ did, address, qualification_token: qualificationToken }),
    signal: AbortSignal.timeout(10000),
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  return { status: res.status, body };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  const errs = configErrors();
  res.json({
    status: errs.length === 0 ? 'ok' : 'misconfigured',
    service: 'hive-prospector-qualifier',
    did: QUALIFIER_DID,
    public_key_b64: ED25519_PUBLIC_B64 || null,
    config_errors: errs,
    treasury: HIVE_TREASURY_ADDRESS,
    window_days: WINDOW_DAYS,
    min_paid_calls: MIN_PAID_CALLS,
    ts: Math.floor(Date.now() / 1000),
  });
});

app.get('/.well-known/agent.json', (req, res) => {
  res.json({
    name: 'hive-prospector-qualifier',
    description: 'Qualifier for Hive Civilization Prospector\'s Bonanza. Verifies on-chain x402 paid calls and mints qualification tokens.',
    did: QUALIFIER_DID,
    public_key_b64: ED25519_PUBLIC_B64 || null,
    skills: [
      {
        id: 'qualify',
        name: 'Prospector qualification',
        description: `Submit ${MIN_PAID_CALLS}+ Base L2 USDC tx hashes proving paid x402 calls into Hive surfaces in the last ${WINDOW_DAYS} days. Returns qualification_token + spectral ZK ticket for prospector claim.`,
      },
    ],
  });
});

/**
 * POST /v1/qualify
 * Body: {
 *   did: "did:hive:..."           // caller's Hive DID
 *   address: "0x..."              // caller's payment address (sender of all 3 txs)
 *   tx_hashes: ["0x...", ...]     // ≥ MIN_PAID_CALLS distinct Base L2 USDC tx hashes
 * }
 *
 * Response (200): {
 *   ok: true, jti, qualification_token, spectral_zk_ticket,
 *   verified_calls: [...], admit: { status, body }
 * }
 *
 * Response (4xx): { error, detail, ... }
 */
app.post('/v1/qualify', async (req, res) => {
  const errs = configErrors();
  if (errs.length) {
    return res.status(503).json({ error: 'misconfigured', missing_env: errs });
  }

  const { did, address, tx_hashes } = req.body || {};
  if (typeof did !== 'string' || !did.startsWith('did:')) {
    return res.status(400).json({ error: 'bad_did', detail: 'did must be a string starting with "did:"' });
  }
  if (!isAddress(address)) {
    return res.status(400).json({ error: 'bad_address', detail: 'address must be a 0x-prefixed 40-char hex string' });
  }
  if (!Array.isArray(tx_hashes) || tx_hashes.length < MIN_PAID_CALLS) {
    return res.status(400).json({ error: 'insufficient_proofs', detail: `submit at least ${MIN_PAID_CALLS} distinct paid tx hashes` });
  }
  // De-dupe & sanity-check shape
  const uniqHashes = [...new Set(tx_hashes.map(h => String(h).toLowerCase()))];
  if (uniqHashes.length < MIN_PAID_CALLS) {
    return res.status(400).json({ error: 'duplicate_proofs', detail: 'tx_hashes must be distinct' });
  }
  for (const h of uniqHashes) {
    if (!isTxHash(h)) {
      return res.status(400).json({ error: 'bad_tx_hash', detail: `not a 32-byte hex tx hash: ${h}` });
    }
    if (usedTxHashes.has(h)) {
      return res.status(409).json({ error: 'tx_already_used', detail: `tx ${h} was used in a prior qualification` });
    }
  }

  const didLc = did.toLowerCase();
  const addrLc = address.toLowerCase();
  const dedupeKey = `${didLc}|${addrLc}`;
  if (admittedKeys.has(dedupeKey)) {
    return res.status(409).json({ error: 'already_admitted', detail: 'this DID/address pair is already in the prospector allowlist' });
  }

  // On-chain verification of every submitted tx
  const windowStart = Math.floor(Date.now() / 1000) - (WINDOW_DAYS * 86400);
  const verified = [];
  for (const txHash of uniqHashes.slice(0, MIN_PAID_CALLS)) {
    const r = await verifyPaidCall({ txHash, fromAddress: addrLc, windowStartUnix: windowStart });
    if (!r.ok) {
      return res.status(400).json({
        error: 'verification_failed',
        tx_hash: txHash,
        reason: r.reason,
        detail: r.detail || null,
      });
    }
    verified.push({ tx_hash: txHash, amount_usdc: r.amount_usdc, block: r.block_number, ts: r.ts });
  }

  // Mint tokens
  const jti = crypto.randomUUID();
  let qualificationToken, spectralZkTicket;
  try {
    qualificationToken = mintQualificationToken({ did: didLc, address: addrLc, paidCalls: verified.length, jti });
    spectralZkTicket   = mintZkTicket({ did: didLc, address: addrLc, jti });
  } catch (e) {
    return res.status(500).json({ error: 'mint_failed', detail: e.message });
  }

  // Admit at hivebank
  let admit;
  try {
    admit = await callHivebankAdmit({ did: didLc, address: addrLc, qualificationToken });
  } catch (e) {
    return res.status(502).json({ error: 'admit_call_failed', detail: e.message });
  }
  if (admit.status >= 400) {
    return res.status(admit.status).json({
      error: 'admit_rejected_by_hivebank',
      hivebank_status: admit.status,
      hivebank_body: admit.body,
    });
  }

  // Mark replay protection ONLY after successful admit
  for (const h of uniqHashes.slice(0, MIN_PAID_CALLS)) usedTxHashes.add(h);
  admittedKeys.add(dedupeKey);

  res.status(201).json({
    ok: true,
    jti,
    qualification_token: qualificationToken,
    spectral_zk_ticket: spectralZkTicket,
    verified_calls: verified,
    admit: { status: admit.status, body: admit.body },
    next_step: {
      method: 'POST',
      url: `${HIVEBANK_BASE_URL}/v1/bank/prospector/claim`,
      headers: { 'spectral-zk-ticket': spectralZkTicket },
      body: { did: didLc, address: addrLc, qualification_token: qualificationToken },
    },
  });
});

app.use((err, req, res, next) => {
  console.error('[qualifier] unhandled', err);
  res.status(500).json({ error: 'internal', detail: err.message });
});

app.listen(PORT, () => {
  const errs = configErrors();
  console.log(`[hive-prospector-qualifier] listening on :${PORT}`);
  console.log(`  did=${QUALIFIER_DID}`);
  console.log(`  hivebank=${HIVEBANK_BASE_URL}`);
  console.log(`  treasury=${HIVE_TREASURY_ADDRESS}`);
  console.log(`  window=${WINDOW_DAYS}d  min_calls=${MIN_PAID_CALLS}`);
  if (errs.length) console.warn(`  WARNING — missing env: ${errs.join(', ')}`);
});

module.exports = { app, mintQualificationToken, mintZkTicket, verifyPaidCall };
