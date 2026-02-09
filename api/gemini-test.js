import { sha256Hex } from './_lib/crypto.js';
const GEMINI_MODEL = “gemini-2.5-flash”;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: 'GEMINI_API_KEY not configured' });
    return;
  }

  const sys = 'Return ONLY valid JSON: {"assistant_response":"ok","suggested_next_intents":[]}';
  const user = 'Respond with {"assistant_response":"ok","suggested_next_intents":[]}';

  const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: user }] }],
      systemInstruction: { parts: [{ text: sys }] }
    })
  });

  let rawText = '';
  try {
    const data = await resp.json();
    rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text || JSON.stringify(data);
  } catch (e) {
    rawText = await resp.text().catch(() => 'Failed to read response');
  }

  const truncated = rawText.slice(0, 500);
  const rawHash = sha256Hex(truncated);

  res.status(200).json({
    status: resp.status,
    ok: resp.ok,
    raw_text: truncated,
    raw_hash: rawHash
  });
}
