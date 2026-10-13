import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encryptPayload, decryptResponse, verifySignature, PAYLOAD_KEY } from '../src/crypto.js';

// Real response captured from https://foscos.fssai.gov.in/gateway/api/auth/csrf-token
// (Wayback Machine snapshot 2026-02-18), signed with the live FoSCoS key.
const REAL_CSRF_RESPONSE = {
  encryptedResponse: '9E1Muq7zZHuhecvBs+t4pZ8cBOABldk7bZAlA1cgFtR+hQ254Z2gZlfdMyH71VDEPJF2vafI5N5WA+JLTGB4gg==',
  signature:
    'Mm4vmbNme6tWTEbiWcFbcOZHpT5rNAmp8FCWDYAckhh5fj+W1DkyH5DN1HB6ETTdQ5T66ZssMwkeYbBR+IQy2ADIVUHfu0ZfYy+kLtuqZptf2b2zd+mRLVLeO1eZsFSJdWol8UU+tioWgkeYweq8pMqeCNEqttsb7RivwFsB+fh5GETzaNIhdvyh/SdOQeusbtt69jcGsEpiLpg0tz5Tcjh/qdUcjkrByDClsqL6SXaqh+V4Z9ryYiHaEJ6HNIkHx1Ou2PV8nhzvXPaqBV41nm17WE4Uw3oDpDA1S6mAciCYAu27EcwWvZXRnPRKcWA21JfCCkwzVU/KeV9lIMptVA==',
};

test('decrypts a real FoSCoS response', () => {
  const json = JSON.parse(decryptResponse(REAL_CSRF_RESPONSE.encryptedResponse));
  assert.deepEqual(json, { message: 'Token generated successfully', status: 'success' });
});

test('verifies the signature of a real FoSCoS response', () => {
  assert.equal(verifySignature(REAL_CSRF_RESPONSE.encryptedResponse, REAL_CSRF_RESPONSE.signature), true);
});

test('rejects a tampered response', () => {
  const tampered = 'A' + REAL_CSRF_RESPONSE.encryptedResponse.slice(1);
  assert.equal(verifySignature(tampered, REAL_CSRF_RESPONSE.signature), false);
  assert.equal(verifySignature(REAL_CSRF_RESPONSE.encryptedResponse, 'not-a-signature'), false);
});

test('payload encryption round-trips with the payload key', () => {
  const body = JSON.stringify({ flrsLicenseNo: '12421012003663' });
  const encrypted = encryptPayload(body);
  assert.match(encrypted, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(decryptResponse(encrypted, PAYLOAD_KEY), body);
});
