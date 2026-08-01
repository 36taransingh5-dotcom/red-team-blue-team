'use strict';
// Thin LLM wrapper. If OPENAI_API_KEY is set, the agents reason and write
// patches with a real model. Otherwise everything degrades gracefully to
// deterministic output so the live demo can never hard-fail.
let client = null;
const model = process.env.OPENAI_MODEL || 'gpt-4o-mini';
const enabled = !!process.env.OPENAI_API_KEY;

if (enabled) {
  try {
    const OpenAI = require('openai');
    client = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
      baseURL: process.env.OPENAI_BASE_URL || undefined,
    });
  } catch (err) {
    console.warn('[llm] openai sdk unavailable, using fallback:', err.message);
  }
}

// Ask the model for a short, in-character line of reasoning. Falls back to
// the provided default so callers always get usable text fast.
async function narrate({ system, user, fallback, maxTokens = 80 }) {
  if (!client) return fallback;
  try {
    const resp = await client.chat.completions.create({
      model,
      max_tokens: maxTokens,
      temperature: 0.7,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    });
    const text = resp.choices?.[0]?.message?.content?.trim();
    return text || fallback;
  } catch (err) {
    console.warn('[llm] narrate failed, using fallback:', err.message);
    return fallback;
  }
}

// Ask the model to produce patched source code. The orchestrator validates
// the result by actually re-running the exploit; if the model output does
// not neutralize the attack, we fall back to the known-good secure template.
async function generatePatch({ vulnType, vulnerableCode, guidance }) {
  if (!client) return null;
  try {
    const resp = await client.chat.completions.create({
      model,
      max_tokens: 400,
      temperature: 0.2,
      messages: [
        {
          role: 'system',
          content:
            'You are a defensive security engineer. Return ONLY valid CommonJS ' +
            'code for the requested module. No markdown fences, no prose.',
        },
        {
          role: 'user',
          content:
            `Vulnerability type: ${vulnType}\n` +
            `Guidance: ${guidance}\n\n` +
            `Rewrite this module to be secure while keeping the same exports and signature:\n\n` +
            vulnerableCode,
        },
      ],
    });
    let code = resp.choices?.[0]?.message?.content?.trim() || '';
    code = code.replace(/^```[a-z]*\n?/i, '').replace(/```$/, '').trim();
    return code || null;
  } catch (err) {
    console.warn('[llm] generatePatch failed, using secure template:', err.message);
    return null;
  }
}

module.exports = { narrate, generatePatch, enabled: !!client, model };
