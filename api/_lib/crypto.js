import { createHash, createHmac } from 'crypto';

export function sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

export function hmacSha256Hex(secret, message) {
  return createHmac('sha256', secret).update(message, 'utf8').digest('hex');
}
