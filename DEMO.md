# Demo Guide

Two things before you show this to anyone:

1. Run `npm run preflight` — it exercises the real stack end-to-end (both front doors, real exploits, real patches, Supabase) and tells you pass/fail before judges do. **Run it again right before judging starts**, not just once this morning — API keys can expire, rate limits happen.
2. Do the full script below **solo, twice** — once through the web UI, once through your coding agent — so the timing and your lines are muscle memory before you're on a clock.

```bash
cd red-team-blue-team
npm run preflight
```

If it prints `✔ 15/15 checks passed — you're demo ready`, you're good. If anything fails, the output tells you exactly what and why — fix that first.

---

## Rehearsing solo

1. `npm run dev`, open `http://localhost:5173`.
2. Click **Launch Simulation**, narrate it to yourself out loud using the script below. Time it — it should land at 45–60s of actual battle plus however long you talk.
3. Open this folder in Claude Code or Cursor, type `activate red team`, watch the transcript render. Time that too.
4. If either run used the fallback template instead of a real LLM patch (check the Blue Team feed — it says `via llm` or `via template`), your OpenAI key may be rate-limited or invalid. The demo still works either way, but decide now whether you want to mention "AI-authored fix" language only when you see `via llm`.

---

## The 3-minute stage pitch

Judging format is a live 3-minute demo for the top 5. This is unforgiving — no room to improvise or wait on a slow API call. Structure:

**0:00–0:20 — Frame it (no clicking yet)**
> "Security teams can't manually test every app continuously. We built two autonomous AI agents that do it for you — Red Team attacks, Blue Team defends, in a closed loop that only counts a fix as done once the attack is re-run and fails."

**0:20–1:00 — Launch, let it cook while you talk over it**
Click **Launch Simulation**. While Red's recon and first exploit play out on screen, narrate what judges are watching, don't wait in silence:
> "That's a real SQL injection — `' OR 1=1` — against a live login endpoint. It just bypassed auth as admin, no credentials. Score drops to 40."

**1:00–1:45 — The fix, and why it's provable, not claimed**
Point at the Blue Team panel and the code diff:
> "Blue detected it, and an LLM rewrote the actual vulnerable file — you're looking at the real before/after diff. But here's the part that matters: we don't trust the AI's own claim that it's fixed. Red immediately re-runs the *exact same attack*. Only when that second attempt fails does the score count it as patched."

Point at the score climbing 40→70→96 as the second vulnerability (IDOR) goes through the same loop, faster since they've seen it once already.

**1:45–2:15 — The differentiator: it's not a separate app**
Switch to your terminal/IDE (already open, folder already loaded):
> "And this isn't a demo app bolted onto an IDE plugin story — it's the same real engine, callable as a tool by any coding agent."

Type `activate red team`, let a few lines of the transcript stream in, then move on — you don't need to wait for it to finish on stage.

**2:15–2:45 — Close on safety, since that's a named judging criterion**
> "Every AI-generated patch is validated against the real exploit before it's trusted — if it fails, we fall back to a vetted hardening automatically. We actually caught the model doing this mid-build: it wrote a plausible-looking access check that could never evaluate true. Our validator caught it and rejected it automatically, with no human involved."

**2:45–3:00 — One-line close**
> "Software that tests and hardens itself, continuously, with every fix independently verified before it's trusted. That's Red Team // Blue Team."

### If a live LLM call is visibly slow (>5s) on stage
Don't stall — keep talking through it ("Blue's reasoning about the root cause right now") or, if you're worried about API latency going in, drop `BEAT_MS=0` in `.env` beforehand and restart — it removes the artificial pacing so the only wait left is genuine network latency, which is usually under 2s per call.

---

## The longer table/walk-up demo (judges visit you, no clock)

You have more room here — use it to show breadth, not just the happy path:

1. Same opening 40 seconds as above.
2. Let the full loop finish uninterrupted — **✔ HARDENED**, score 96.
3. Scroll to **Battle History** at the bottom: "This isn't just in-memory — every run persists to Supabase, so the score history and what got patched survives restarts."
4. Switch to the IDE, run `activate red team` there too, and while it's running, mention: "Same engine, but it boots its own isolated sandbox — it doesn't even share files with the browser instance, so two people could run this against the same repo at once without corrupting each other's state." *(This is a real fix we made mid-build, not a hypothetical — worth saying if asked how you know it's isolated.)*
5. If they ask "what's actually vulnerable" — open `server/sandbox/vuln/loginQuery.js` and `accountAccess.js` in the editor and show the live file literally change on disk when Blue patches it.
6. If they ask "what happens if the AI's fix is wrong" — this is your best answer, use the real story: "It happened during testing — gpt-4o-mini wrote an admin check comparing a numeric user ID to the string `'admin'`, which can never be true. Our validator doesn't just check the code runs, it checks the actual security decision is correct for four cases: owner, stranger, admin, anonymous. It caught this and fell back to a vetted template automatically."

---

## Anticipated judge questions (tied to the actual judging criteria)

| Criterion | Your answer |
|---|---|
| **Technical execution** | Real HTTP exploits against a real (if minimal) vulnerable app, real file-level code patching with hot-reload, no mocked steps. Show the preflight script output if asked for proof. |
| **AI autonomy** | Both agents reason and act without a human in the loop per cycle — the only human action is clicking "launch" or typing one sentence. |
| **Safety / responsible AI design** | Closed-loop verification (a patch only counts if re-attack fails); semantic validation of patches before they ever touch the live sandbox; automatic fallback to a vetted template when an LLM patch is wrong; everything runs against a self-contained localhost sandbox with fabricated data, never a real target. |
| **UX clarity** | Two front doors to the same real engine — a mission-control UI for a visual demo, and a one-sentence coding-agent command for the "it lives in your workflow" story. |
| **Real-world applicability** | Roadmap: point Red at your actual open project instead of the bundled demo app, then GitHub-integrate so every PR gets an autonomous Red review + Blue validation before merge. |
| **Product thinking** | It's not a dashboard or a report generator — the AI takes real actions (attacks, file writes) and the loop is judged by an independent re-test, not by the AI's own say-so. |

---

## If something breaks live

- **Score doesn't move / feed stays empty**: check the browser console or just re-run `npm run preflight` in a second terminal — it'll tell you which of the two servers (`:3001` control, `:4000` sandbox) is down.
- **"Simulation already running" error**: something triggered a run that's still going (maybe your own rehearsal). Wait ~30s or restart `npm run dev`.
- **MCP tool doesn't show up in Claude Code/Cursor chat**: you probably need to re-open the folder or approve the project MCP server (Claude Code prompts once per project) — don't debug this live, fall back to the web UI.
- **Whole thing on fire**: web UI is the safer of the two surfaces since it's fewer moving parts (no MCP handshake) — lead with it, treat the IDE moment as a bonus beat you can skip if you're already tight on the 3-minute clock.
