/**
 * Qualifier crypto path test — no RPC, no hivebank.
 * Verifies HMAC qualification_token + Ed25519 ZK ticket round-trip.
 */
const crypto = require('crypto');
const nacl = require('tweetnacl');

// Generate a fresh keypair for the test
const kp = nacl.sign.keyPair();
const ED25519_SECRET_B64 = Buffer.from(kp.secretKey).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ED25519_PUBLIC_B64 = Buffer.from(kp.publicKey).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

process.env.PROSPECTOR_QUALIFIER_SECRET = 'test-secret-do-not-use-in-prod';
process.env.HIVE_INTERNAL_KEY = 'test-internal-key';
process.env.ZK_TICKET_ED25519_SECRET_B64 = ED25519_SECRET_B64;
process.env.ZK_TICKET_ED25519_PUBLIC_B64 = ED25519_PUBLIC_B64;

const { mintQualificationToken, mintZkTicket } = require('../server.js');

function fromB64url(s) {
  let str = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

let pass = 0, fail = 0;
function assert(cond, msg) {
  if (cond) { pass++; console.log(`  ✓ ${msg}`); }
  else      { fail++; console.error(`  ✗ ${msg}`); }
}

console.log('TEST: HMAC qualification_token round-trip');
const jti = crypto.randomUUID();
const token = mintQualificationToken({
  did: 'did:hive:test-agent-001',
  address: '0x' + 'a'.repeat(40),
  paidCalls: 3,
  jti,
});
assert(typeof token === 'string', 'token is a string');
assert(token.includes('.'), 'token has body.sig form');
const [body, sig] = token.split('.');
const recoveredPayload = JSON.parse(fromB64url(body).toString());
assert(recoveredPayload.typ === 'hive-prospector-qualification', 'payload typ correct');
assert(recoveredPayload.jti === jti, 'jti round-trips');
assert(recoveredPayload.paid_calls === 3, 'paid_calls round-trips');
assert(recoveredPayload.exp > recoveredPayload.iat, 'exp > iat');
// HMAC verifies
const expectedSig = crypto.createHmac('sha256', process.env.PROSPECTOR_QUALIFIER_SECRET).update(body).digest();
const actualSig = fromB64url(sig);
assert(crypto.timingSafeEqual(expectedSig, actualSig), 'HMAC signature verifies');
// Tampered body fails
const tamperedToken = body.slice(0, -2) + 'XX.' + sig;
const [tBody, tSig] = tamperedToken.split('.');
let tamperOk = false;
try {
  const expSig2 = crypto.createHmac('sha256', process.env.PROSPECTOR_QUALIFIER_SECRET).update(tBody).digest();
  tamperOk = crypto.timingSafeEqual(expSig2, fromB64url(tSig));
} catch { tamperOk = false; }
assert(!tamperOk, 'tampered body fails HMAC');

console.log('\nTEST: Ed25519 ZK ticket round-trip');
const ticket = mintZkTicket({
  did: 'did:hive:test-agent-001',
  address: '0x' + 'b'.repeat(40),
  jti,
});
const [tbody, tsig] = ticket.split('.');
const ticketPayload = JSON.parse(fromB64url(tbody).toString());
assert(ticketPayload.typ === 'hive-spectral-zk-ticket', 'ticket typ correct');
assert(ticketPayload.route === 'prospector', 'ticket bound to prospector route');
assert(ticketPayload.pubkey === ED25519_PUBLIC_B64, 'pubkey embedded');
// Signature verifies with our public key
const verified = nacl.sign.detached.verify(
  Buffer.from(tbody),
  fromB64url(tsig),
  fromB64url(ED25519_PUBLIC_B64),
);
assert(verified, 'Ed25519 signature verifies with embedded pubkey');
// Tampered body fails verify
const badBody = tbody.slice(0, -2) + 'YY';
const badVerified = nacl.sign.detached.verify(Buffer.from(badBody), fromB64url(tsig), fromB64url(ED25519_PUBLIC_B64));
assert(!badVerified, 'tampered body fails Ed25519 verify');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
