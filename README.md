# Red Team // Blue Team — Autonomous Cyber Range

> Autonomous offensive and defensive AI agents that continuously attack and defend software to improve its security.

Built for the **Cursor Cybersecurity London Hackathon 2026** — _"Building the infrastructure for AI-native cybersecurity."_

Two AI agents fight over a **real, deliberately vulnerable Banking API**:

- **🔴 Red Team** — an ethical hacker. Performs reconnaissance and launches **real HTTP exploits** (SQL injection auth bypass, IDOR / broken access control).
- **🔵 Blue Team** — a defensive engineer. Detects each attack, **rewrites the actual vulnerable source code**, hot-reloads it into the running app, and verifies the fix.

The loop is genuinely autonomous and _real_: nothing is faked. Red really breaks in, Blue really patches the code, and every patch is **validated by re-running the exploit**. The application's security score climbs from **40 → 96** as it hardens itself in front of you.

There are **two ways to run it**: a standalone Mission Control web UI, or — the more interesting one — **directly inside your coding agent's chat** (Claude Code, Cursor, or Codex), via [MCP](#run-it-inside-your-coding-agent-mcp). Just type "activate red team" and watch it happen right there in the IDE.

---

## Why it's not just another AI wrapper

- The agents **take real actions**: real exploit traffic, real file rewrites, real hot-reload, real re-tests.
- **Closed-loop verification** — a patch only counts if Red's follow-up attack now fails (HTTP 401). If an LLM-generated patch doesn't hold, Blue falls back to a vetted hardening and re-verifies.
- **You watch the code change live** — the "Live Code Remediation" panel shows the real before/after of the swapped module.

---

## Architecture

```
  Mission Control UI (:5173)      Your coding agent's chat
  (browser, SSE timeline)         (Claude Code / Cursor / Codex)
              │                              │
              │  HTTP + SSE                  │  MCP (stdio)
              ▼                              ▼
      Control API (:3001)          mcp/server.js — same tool,
              │                    embeds its own sandbox + agents
              ▼                              │
        Orchestrator + Agents  ◄──────────────┘
           │                 │
     🔴 Red Team        🔵 Blue Team
     (real HTTP)        (rewrites code)
           │                 │
           ▼                 ▼
  Vulnerable "Banking API Demo" sandbox
     swappable modules → hot-reloaded per request
           │
           ▼
     Supabase (run history, shared across both front doors)
```

Two front doors, one real engine: the web UI drives the orchestrator over HTTP/SSE; the MCP server (`mcp/server.js`) embeds the *exact same* sandbox/agents/orchestrator code directly in-process and exposes it as a tool call. Both write to the same Supabase tables, so run history is shared regardless of which one you used.

- **Sandbox** (`server/sandbox`) — Express + Node's built-in `node:sqlite`. Security-critical logic lives in `sandbox/vuln/*.js`, re-`require`d on every request so Blue's patches apply live with **no restart**.
- **Agents** (`server/agents`) — `red.js` sends real exploits; `blue.js` reads the vulnerable module, asks the LLM for a hardened rewrite, writes it, and keeps a vetted fallback. `llm.js` wraps OpenAI (or any OpenAI-compatible endpoint) and **degrades to deterministic output if no key is set**, so the demo can never hard-fail.
- **Orchestrator** (`server/orchestrator.js`) — runs the attack → patch → verify battle loop and streams a live timeline over SSE.
- **MCP server** (`mcp/server.js`) — the same battle loop, exposed as an `activate_red_team` tool for any MCP-compatible coding agent. Picks a free port for its own sandbox automatically if `:4000` is already taken by the standalone web app, so both can run side by side without conflicting.

The two seeded vulnerabilities:

| # | Vulnerability | Endpoint | Exploit | Fix Blue applies |
|---|---|---|---|---|
| 1 | SQL Injection (auth bypass) | `POST /api/login` | `username: ' OR 1=1 --` | parameterized query |
| 2 | Broken Access Control (IDOR) | `GET /api/accounts/:id` | no auth header | ownership + auth enforcement |

---

## Run it

```bash
cd red-team-blue-team
npm install
npm run dev
```

Then open **http://localhost:5173** and click **▶ LAUNCH SIMULATION**.

**Before demoing to anyone**, run the preflight check — it exercises the real stack end-to-end (both front doors, real exploits, real patches, Supabase) and tells you pass/fail before judges do:

```bash
npm run preflight
```

See [DEMO.md](DEMO.md) for the actual talking-point script (3-minute stage version and a longer table-demo version), timing, and a Q&A cheat sheet mapped to the hackathon's judging criteria.

Requires Node 20.6+ (uses built-in `node:sqlite`; tested on Node 24). No native compilation, no database to set up.

### Enable live LLM reasoning (optional but recommended for the demo)

The agents reason and generate patches with a real model when a key is present:

```bash
cp .env.example .env
# then edit .env:
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
# optional: any OpenAI-compatible endpoint
# OPENAI_BASE_URL=https://api.openai.com/v1
```

Restart `npm run dev`. The header chip flips from `🧠 fallback mode` to the live model name, and Blue's patches become genuinely LLM-authored (still validated by re-attack).

Tune pacing with `BEAT_MS` in `.env` (lower = faster; `0` = instant, good for testing).

### Enable persistent history (optional — Supabase)

Without this, everything still works — the app just keeps run history in memory only (lost on restart). To persist every run and its full event timeline:

1. Create a free project at [supabase.com/dashboard](https://supabase.com/dashboard).
2. In the SQL Editor, run [`supabase/schema.sql`](supabase/schema.sql) once (creates `runs` + `run_events`, RLS enabled with no policies).
3. Add to `.env`:
   ```
   SUPABASE_URL=https://xxxxx.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=sb_secret_...
   ```
   Use the **service_role / secret** key (Project Settings → API), never the `anon`/publishable one — the server uses it to bypass RLS by design, and it must never reach the browser.

Restart `npm run dev`. The header chip flips from `💾 in-memory only` to `💾 Supabase`, and a **Battle History** panel at the bottom of the page shows past runs pulled straight from the database.

---

## Run it inside your coding agent (MCP)

This is the more interesting way to run it: no browser, no separate server — just type **"activate red team"** in your coding agent's chat and it plays out right there, with a full narrated transcript and real before/after code diffs in markdown.

It works because `mcp/server.js` exposes the exact same engine as an [MCP](https://modelcontextprotocol.io) tool. `npm install` (already done if you followed [Run it](#run-it)) pulls in everything needed — nothing extra to build.

**Claude Code** — a project-scoped [`.mcp.json`](.mcp.json) is already checked in. Just open this folder (`red-team-blue-team/`) in Claude Code; on first use it'll ask you to approve the project MCP server — say yes, then type:
> activate red team

**Cursor** — same idea, config already at [`.cursor/mcp.json`](.cursor/mcp.json). Open the folder in Cursor, check **Settings → MCP** to confirm `red-team-blue-team` shows as connected (may need a toggle/refresh the first time), then just ask it to activate red team in chat.

**Codex CLI** — register it once:
```bash
codex mcp add red-team-blue-team -- node --experimental-sqlite --no-warnings mcp/server.js
```
(run from inside `red-team-blue-team/`, or use an absolute path to `mcp/server.js`). Then ask Codex to activate red team.

Two tools are exposed:
- **`activate_red_team`** — runs the full attack → patch → verify battle and returns the complete transcript.
- **`redteam_history`** — pulls past runs from Supabase, if configured (works from any front door, since history is shared).

The MCP server boots its own in-process copy of the vulnerable sandbox on first use, automatically picking a free port if `:4000` is already taken by the standalone web app — so you can run both at once without conflicts.

---

## Testing a real, arbitrary codebase (not just the built-in demo)

Everything above targets one fixed, known-vulnerable sandbox — reliable for a demo, but it's not scanning "a codebase," it's exploiting two bugs written in advance. `activate_red_team` also accepts `targetDir` + `targetUrl`, which points Red at a **real, arbitrary local Node/Express app it has never seen**: it reads the source, proposes concrete vulnerabilities via the LLM, sends real HTTP requests to try to prove them, and — if one lands — Blue patches the actual file and Red re-attacks to verify, exactly like the built-in demo.

```
activate red team on /path/to/some/project at http://localhost:3000
```

(Your coding agent maps that phrasing to `targetDir`/`targetUrl` automatically — the tool's description tells it how.)

A ready-made second target ships in [`test-fixtures/mini-notes-api`](test-fixtures/mini-notes-api) — a different domain with three different vulnerability classes (SQL injection, broken access control, path traversal — the last two aren't in the built-in demo at all). Verified live: a single run found and independently fixed all three of SQL injection, broken access control, and a related missing-authentication issue in one pass, having first tried and correctly ruled out five other guesses along the way. See its README for how to run it with hot-reload.

**Be clear-eyed about what's different here versus the built-in demo:**

- **Only localhost/127.0.0.1** — hard-enforced in code (`assertLocalhost` in `agents/genericRed.js`), not a suggestion. This never attacks a remote target.
- **It can legitimately find nothing.** Not every codebase has an exploitable bug, and this is one AI's best attempt in one pass — a clean result doesn't mean the app is secure, only that this attempt didn't find an issue.
- **Verification is weaker than the built-in demo's.** The Banking Demo's patches are checked against four hand-written, known-correct scenarios (owner/stranger/admin/anonymous) before they're ever trusted. There's no way to write that generically for code we've never seen — so here, the only pre-write check is "does it parse" (`node --check`), and the *real* proof is re-running the same exploit. That's a necessary check, not a sufficient one: during testing, one generated patch happened to block the specific attack by accident (it hardcoded a fake logged-in user) without implementing real authentication at all. Review AI-generated patches before trusting them in anything real.
- **The target must hot-reload on file changes** (nodemon, `node --watch`, etc.) for the live re-verification to mean anything. Without it, a *correct* patch and a *bad* one look identical on retest — the process serving requests never picked up the change either way.
- **Real files get modified.** A backup is always written first (`.redteam-backups/` next to the target, gitignored), and if the retest fails, the file is reverted rather than left in an unverified state — but this is genuinely mutating your project, not a disposable sandbox copy.
- **Finds and fixes multiple distinct vulnerabilities per run** (deduped so a few depth-guesses for the same bug don't count as separate findings), working through them one at a time — but it's still one recon pass over a heuristically-shortlisted set of files, not an exhaustive sweep. It can, and sometimes does, miss something real.

---

## 90-second demo script

1. **Open the command center.** "This is a live, deliberately vulnerable banking API. Two autonomous AI agents are about to fight over it."
2. **Click Launch.** Red does recon, then lands a **SQL injection** — bypasses login as `admin`, exposes a $9.8M balance. Score drops to 40.
3. **Blue reacts autonomously** — detects the threat, **rewrites `loginQuery.js`** to a parameterized query (shown live in the diff panel), hot-reloads it.
4. **Red re-attacks the same endpoint — now HTTP 401.** "The patch is verified by re-running the exploit. It's really fixed."
5. Red **pivots** to a second flaw (IDOR), reads another user's account with no auth — Blue patches `accountAccess.js`, Red is blocked again.
6. **Final sweep: both attacks dead. Score 96. ✔ HARDENED.** "The software attacked and defended itself, and got measurably safer — no human in the loop."

**Optional closing beat:** flip to your terminal/IDE, type "activate red team" in Claude Code or Cursor, and let the exact same battle play out as a narrated transcript in the coding agent's own chat. "This isn't a separate demo app bolted onto an IDE integration — it's the same real engine, callable from anywhere an AI agent can make a tool call."

---

## Safety & responsible design

- Everything runs against a **self-contained sandbox on localhost** with fabricated data. No external targets, ever.
- The exploits are the two classic, well-understood OWASP categories — used here to *demonstrate detection and remediation*, not to arm attackers.
- Blue's autonomy is bounded: patches are confined to the sandbox's swappable modules and are only accepted after **automated re-verification**; anything that fails validation is flagged for human review.
- Validation is **semantic, not just structural** — a candidate patch is loaded in an isolated temp file and exercised with the exact security-relevant cases (owner access, stranger denial, admin override, unauthenticated denial; injection payload vs. legitimate login) before it's ever written into the live sandbox. This was tightened after live testing surfaced a real LLM failure mode: a syntactically valid but semantically broken access check (`callerId === 'admin'`, which can never be true) that a shape-only check would have missed. It's now caught and rejected automatically, falling back to the vetted template.
- The MCP server's sandbox is **fully isolated from the standalone web app's**, not just on a different port — it gets its own copy of the mutable vulnerable modules (`VULN_DIR_OVERRIDE`) on a private path. This was also a real bug caught during testing: without it, two orchestrator instances running close together in time (e.g. a preflight check exercising both front doors back to back) would race each other writing patches to the same physical files on disk.

## Roadmap

- ~~**Phase 2:** Cursor / Claude Code / Codex integration~~ — **done**, via the [MCP server](#run-it-inside-your-coding-agent-mcp).
- ~~**Phase 2.5:** point Red at the actual project open in the IDE, not just the bundled demo~~ — **done**, via [`targetDir`/`targetUrl`](#testing-a-real-arbitrary-codebase-not-just-the-built-in-demo), including finding and fixing multiple distinct vulnerability types in one run. Next step for this phase: widen the LLM's recon beyond a heuristic file pre-filter, so it isn't limited to files that happen to match suspicious regex patterns.
- **Phase 3:** GitHub integration — every PR triggers an autonomous Red review + Blue validation before merge.
