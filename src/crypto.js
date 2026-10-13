// FoSCoS wraps its JSON traffic in AES-128-ECB (PKCS7) and signs responses
// with RSA-SHA256. The keys below are the ones the public FoSCoS Angular
// frontend ships (obfuscated) in its bundle; they are not secrets.
import crypto from 'node:crypto';
import fs from 'node:fs';

export const PAYLOAD_KEY = 'T#M&L^wP#B#1878@';
export const RESPONSE_KEY = 'K@G#H^zN#Q#1512&';

// Served by FoSCoS at /assets/keys/resPublic.pem
export const RESPONSE_PUBLIC_KEY = fs.readFileSync(
  new URL('./foscos-response-public.pem', import.meta.url),
  'utf8',
);

export function encryptPayload(text, key = PAYLOAD_KEY) {
  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]).toString('base64');
}

export function decryptResponse(base64, key = RESPONSE_KEY) {
  const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null);
  return Buffer.concat([decipher.update(base64, 'base64'), decipher.final()]).toString('utf8');
}

export function verifySignature(encryptedResponse, signature, publicKey = RESPONSE_PUBLIC_KEY) {
  try {
    return crypto.verify(
      'sha256',
      Buffer.from(encryptedResponse, 'utf8'),
      publicKey,
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
}
