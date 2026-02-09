import { sha256Hex } from './_lib/crypto.js';

export default async function handler(req, res) {
  try {
    const hash = sha256Hex('test');
    res.status(200).json({ status: 'ok', hash });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
