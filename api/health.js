export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  res.status(200).json({
    status: 'ok',
    issuer_key_id: process.env.KERNEL_ISSUER_KEY_ID || 'KERNEL_V4_ISSUER_01',
    has_gemini_key: !!process.env.GEMINI_API_KEY,
    has_signing_secret: !!process.env.KERNEL_SIGNING_SECRET
  });
}
