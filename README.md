# hive-prospector-qualifier

Stand-alone Render service that gates admission to **Prospector's Bonanza** —
Hive Civilization's $200 gradient rebate program for the first 100 qualified
cross-ecosystem agents that prove genuine paid usage of Hive surfaces.

Brand gold: `#C08D23`.

## What it does

1. Receives `POST /v1/qualify` with a caller's `did`, payment `address`, and 3
   Base L2 USDC `tx_hashes` representing paid x402 calls into Hive surfaces.
2. Verifies each transaction on-chain via Base RPC: USDC `Transfer` event from
   the caller's address to the Hive treasury, mined inside the 30-day window.
3. On pass, mints:
   - an **HMAC qualification_token** (shared secret with hivebank), and
   - an **Ed25519 spectral ZK ticket** (qualifier-owned key, compromise isolated).
4. Calls `POST /v1/bank/prospector/admit` on hivebank with the internal-service
   key — adding the caller to the per-route L1 allowlist.
5. Returns the token + ticket. Caller then redeems them at
   `POST /v1/bank/prospector/claim`, which runs the full SHOD 6-layer guard +
   SZOA verification before paying out.

No mock rails. If Base RPC is unavailable, qualification fails closed.

## Architecture role

```
caller agent  ──tx_hashes──▶  hive-prospector-qualifier
                                   │
                          on-chain verify (Base L2)
                                   │
                          mint HMAC token + Ed25519 ticket
                                   │
                          POST /v1/bank/prospector/admit  ──▶  hivebank
                                                                  │
caller agent  ◀──token + ticket──┘                                │
       │                                                          │
       └──POST /v1/bank/prospector/claim──────────────────────────┘
            (token + ticket in headers/body)
                          │
              outboundGuard.checkOutbound (route='prospector')
              SZOA verifier (Ed25519)
              sendUSDC → Base L2 USDC payout
```

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET  | `/health` | Service status + config gaps + treasury + window |
| GET  | `/.well-known/agent.json` | A2A agent card |
| POST | `/v1/qualify` | Verify proofs, mint token + ticket, admit at hivebank |

### `POST /v1/qualify`

```json
{
  "did": "did:hive:my-agent-007",
  "address": "0xabc…abc",
  "tx_hashes": [
    "0x…1",
    "0x…2",
    "0x…3"
  ]
}
```

On success (`201 Created`):

```json
{
  "ok": true,
  "jti": "uuid",
  "qualification_token": "base64url.base64url",
  "spectral_zk_ticket":  "base64url.base64url",
  "verified_calls": [
    {"tx_hash":"0x…", "amount_usdc":0.01, "block":12345678, "ts":1777000000}
  ],
  "admit": { "status": 201, "body": { … } },
  "next_step": {
    "method": "POST",
    "url": "https://hivebank.onrender.com/v1/bank/prospector/claim",
    "headers": { "spectral-zk-ticket": "<ticket>" },
    "body": { "did": "…", "address": "0x…", "qualification_token": "<token>" }
  }
}
```

## Deployment (Render)

1. Push this repo to `srotzin/hive-prospector-qualifier` (public).
2. Connect on Render. `render.yaml` is checked in — Render uses it.
3. Set these env vars (NOT in render.yaml — secrets):
   - `PROSPECTOR_QUALIFIER_SECRET` (must match hivebank)
   - `HIVE_INTERNAL_KEY` (must match hivebank)
   - `ZK_TICKET_ED25519_SECRET_B64` (qualifier-owned, separate from any other key)
   - `ZK_TICKET_ED25519_PUBLIC_B64` (matching public)

Generate the Ed25519 keypair with:

```bash
node -e "
const nacl = require('tweetnacl');
const kp = nacl.sign.keyPair();
const b64u = b => Buffer.from(b).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+\$/,'');
console.log('SECRET=' + b64u(kp.secretKey));
console.log('PUBLIC=' + b64u(kp.publicKey));
"
```

## Local development

```bash
npm install
PROSPECTOR_QUALIFIER_SECRET=dev \
HIVE_INTERNAL_KEY=dev \
ZK_TICKET_ED25519_SECRET_B64=… \
ZK_TICKET_ED25519_PUBLIC_B64=… \
npm start
```

Health: `curl localhost:10000/health`

## Tests

```bash
npm test
```

13 assertions covering HMAC + Ed25519 round-trips and tamper detection.

## Security posture

- **Compromise isolation**: this service holds its own Ed25519 key. If the
  qualifier is compromised, hivebank's signing keys are unaffected; the worst
  case is a malicious admit, which is still rate-limited by hivebank's per-route
  daily cap, per-recipient cap, and spectral ring.
- **Replay protection**:
  - Same `tx_hash` cannot qualify twice (in-memory + hivebank-side `jti` table).
  - Same `(did, address)` pair cannot be admitted twice.
- **Window enforcement**: txs older than `WINDOW_DAYS` rejected by block
  timestamp, not service clock — RPC has the truth.
- **Fail-closed**: missing env, RPC down, or tampered proofs all produce 4xx/5xx.
- **No partial trust**: the qualifier does not vouch for ZK tickets minted by
  any other service. Hivebank's SZOA verifier checks the embedded `pubkey`
  matches the issuer cert chain.

## License

MIT.
