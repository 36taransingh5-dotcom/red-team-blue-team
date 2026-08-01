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

// Generic-target mode has no hand-written fallback — there's no way to
// deterministically "find a vulnerability" in code we've never seen. If
// there's no client, callers must handle a null return as "can't run in
// this mode without a real LLM," not silently degrade like the fixed demo.
async function askJSON({ system, user, maxTokens = 700, temperature = 0.2 }) {
  if (!client) return null;
  try {
    const resp = await client.chat.completions.create({
      model,
      max_tokens: maxTokens,
      temperature,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    });
    let text = resp.choices?.[0]?.message?.content?.trim() || '';
    text = text.replace(/^```[a-z]*\n?/i, '').replace(/```$/, '').trim();
    try {
      return JSON.parse(text);
    } catch {
      const match = text.match(/\{[\s\S]*\}/);
      if (match) { try { return JSON.parse(match[0]); } catch { /* fall through */ } }
      console.warn('[llm] askJSON: model did not return valid JSON:', text.slice(0, 200));
      return null;
    }
  } catch (err) {
    console.warn('[llm] askJSON failed:', err.message);
    return null;
  }
}

// Same idea as generatePatch, but for an arbitrary file/vulnerability the
// model is seeing for the first time — no vetted template to fall back to,
// so the caller must validate (syntax check + re-attack) before trusting it.
async function generateGenericPatch({ before, name, description, requestUsed }) {
  if (!client) return null;
  try {
    const resp = await client.chat.completions.create({
      model,
      max_tokens: 900,
      temperature: 0.2,
      messages: [
        {
          role: 'system',
          content:
            'You are a defensive security engineer. Return ONLY the full corrected ' +
            'source file, as valid code, with no markdown fences and no prose. ' +
            'Preserve all existing exports, routes, and behavior that are not part ' +
            'of the vulnerability being fixed.',
        },
        {
          role: 'user',
          content:
            `Vulnerability: ${name}\n` +
            `Description: ${description}\n` +
            `The exploit that proved this works: ${JSON.stringify(requestUsed)}\n\n` +
            `Rewrite this file to fix the vulnerability while changing as little else as possible:\n\n` +
            before,
        },
      ],
    });
    let code = resp.choices?.[0]?.message?.content?.trim() || '';
    code = code.replace(/^```[a-z]*\n?/i, '').replace(/```$/, '').trim();
    return code || null;
  } catch (err) {
    console.warn('[llm] generateGenericPatch failed:', err.message);
    return null;
  }
}

module.exports = { narrate, generatePatch, askJSON, generateGenericPatch, enabled: !!client, model };
