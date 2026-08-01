# mini-notes-api

A tiny, deliberately vulnerable Express app — a ready-made second target for trying the **generic** (arbitrary-codebase) Red/Blue flow against, separate from the built-in Banking Demo. Different domain, three different vulnerability classes (including path traversal, which the Banking Demo doesn't have at all), so a successful run here proves the mechanism generalizes and can find real variety, not just one pattern it was tuned on. Verified live: a single run found and fixed all three of SQL injection, broken access control, *and* missing authentication in one pass, plus reported five other guesses it correctly ruled out along the way.

Three real, live-exploitable bugs:
1. **SQL injection** — `GET /notes/search?q=...` concatenates the search term straight into the query. Try `?q=' OR 1=1--`.
2. **Broken access control** — `GET /notes/:id` returns any note with no auth check.
3. **Path traversal** — `GET /notes/:id/attachment?file=...` reads whatever file you ask for, unsanitized. Try `?file=../secrets.env`.

## Run it (with hot-reload, so Blue's patches actually take effect live)

```bash
cd red-team-blue-team
npm install   # pulls in nodemon, used below
NODE_OPTIONS=--experimental-sqlite npx nodemon --watch test-fixtures/mini-notes-api test-fixtures/mini-notes-api/server.js
```

`NODE_OPTIONS` is needed because this fixture uses Node's built-in `node:sqlite` — nodemon spawns `node` itself, so the flag has to come in via the environment rather than the command line.

It listens on `:4500` by default (override with `PORT=...`).

**Hot-reload matters here** — unlike the built-in Banking Demo (which re-`require`s its vulnerable modules fresh on every request, by design), this is a plain Express app. If you run it with plain `node server.js` instead of nodemon, Blue's patch gets written to disk correctly, but the *already-running process* never picks it up, so the verification re-attack will look like it failed even when the patch was actually correct. Restart-on-change tooling (nodemon, `node --watch`, etc.) is what makes the live re-verification step meaningful for any *real* target, not just this fixture.

## Try it

In Claude Code, Cursor, or Codex (with the `red-team-blue-team` MCP server registered — see the main README):

> activate red team on /Users/you/path/to/red-team-blue-team/test-fixtures/mini-notes-api at http://localhost:4500

Or call the tool directly with `targetDir` + `targetUrl` set to that path and URL.
