# CodeAtlas

CodeAtlas audits a public GitHub repository and produces a full architecture, security,
and health report: a 0–100 health score, detected frameworks and database models,
extracted REST API routes, a security-leak scan, an AST view of the largest source file,
and a repo-aware AI chat to ask follow-up questions.

This version (v2) adds a real database layer, accounts, scan history, and fixes several
bugs found while reviewing the original code - see [`CHANGES.md`](./CHANGES.md) for the
full list.

## Quick start

**Screen flow:** everyone first sees the **landing page** (what CodeAtlas does and how it works) with
**Sign in / Sign up** at the top-right. **Open the Analyzer** leads to the **Home** screen where you paste a repo
URL once you are signed in. There is no first-run Setup box: if `JWT_SECRET` is missing the server generates one
itself. Keys can still be changed later from the **Settings** button in the Analyzer header.

**macOS/Linux:**
```bash
git clone <your-fork-url>
cd CodeAtlas
npm run setup                        # installs backend dependencies
cp backend/.env.example backend/.env
```

**Windows (PowerShell):**
```powershell
git clone <your-fork-url>
cd CodeAtlas
npm run setup                        # installs backend dependencies
Copy-Item backend\.env.example backend\.env
```
(`cp` also works in PowerShell - it's aliased to `Copy-Item` - just make sure it's
`cp`, not `cd`. `cd`/`Set-Location` only takes one path and will error on a second
argument, which is a very easy typo to make.)

Open `backend/.env` and set a `JWT_SECRET` (any long random string works - this one
command works identically in both bash and PowerShell since it just calls `node`):

```
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

**You also need a MongoDB instance to point `MONGODB_URI` at** - pick one:

- **Local:** install [MongoDB Community Server](https://www.mongodb.com/try/download/community)
  and run `mongod` (it defaults to `mongodb://127.0.0.1:27017`, which matches
  `.env.example` out of the box - no further config needed).
- **Hosted (no local install):** create a free cluster on
  [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register) and set
  `MONGODB_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net` in `.env`.

The server won't start without a reachable database - `npm run dev` will exit with
`❌ Failed to connect to MongoDB` and a hint to check `MONGODB_URI` if one isn't
running.

Then, either platform:

```
npm run seed                  # optional: creates demo@codeatlas.dev / password123
npm run dev                    # starts the API + serves the dashboard
```

Open **http://localhost:5001** - the frontend and API now run on the same origin/port,
so there's nothing else to start.

> **Don't double-click `frontend/index.html`.** Opening it directly gives it a
> `file:///` address instead of `http://localhost:5001`, which used to break every
> API call with a confusing CORS error. The dashboard now detects this and falls
> back to `http://localhost:5001` automatically - but the backend still has to
> actually be running (`npm run dev`) for that to work, so open the app through
> the URL above rather than the file itself.

**Node version:** requires **Node 22.5 or newer** (used for its modern JS features
and to stay current with the rest of the toolchain - no built-in SQLite dependency
here, storage is MongoDB, see below). Run `node --version` if you're not sure;
`nvm install 22 --lts` (or the Windows equivalent, `nvm-windows`) if you need to
switch.

A server-wide GitHub token is optional but recommended (`GITHUB_TOKEN` in `.env`,
via the Setup screen) - it raises the anonymous GitHub API rate limit from 60
requests/hour to 5,000/hour. A fine-grained token with no scopes is enough for
scanning public repos. This is separate from the personal GitHub token every
account provides at signup (see "The new screen flow" below) - that one is
required, verified against GitHub, and is what actually powers each signed-in
user's own scans and their private/org repo listing.

## What's inside

```
CodeAtlas/
├── backend/
│   ├── analyzer/        # scanning/extraction engine (unchanged logic, a few bugfixes)
│   ├── db/
│   │   ├── mongoClient.js # connection singleton, index setup
│   │   ├── queries.js     # every database read/write lives here
│   │   └── seed.js        # creates a demo account
│   ├── middleware/auth.js  # JWT: optionalAuth / requireAuth
│   ├── routes/            # auth, scan history, repository trends
│   ├── utils/validate.js  # input validation (closes the injection bug - see CHANGES.md)
│   ├── tests/             # node --test unit tests
│   └── server.js
└── frontend/index.html    # single-file dashboard (Tailwind + vanilla JS)
```

> A GitHub Action that audits every PR and comments the report is a natural next
> addition but isn't included yet - see "Ideas to take this further" below.

## The new screen flow

The dashboard is now gated behind four screens instead of one always-visible
page:

1. **Setup** (first run only) - paste or generate a `JWT_SECRET`, optionally
   add a server-wide `GITHUB_TOKEN`. Both are written straight into
   `backend/.env` via `POST /api/setup` and take effect immediately (no
   restart). "Skip for now" just marks setup as seen and keeps the server's
   temporary session secret - fine for a quick local look, but tokens
   issued that way stop working the next time the server restarts. (This
   server-wide token only raises the anonymous rate limit - it's separate
   from the personal token every account has, below.)
2. **Sign in / Sign up** - a full-page version of the existing auth form.
   Logging in is now required to reach Home (previously scanning worked
   anonymously; see CHANGES.md-style note below if you want that back).
   **Creating an account requires a personal GitHub token** (verified
   against GitHub before the account is created) - it's what every scan
   actually runs on, and it's what unlocks private/org repos in the "Your
   Repositories" panel below. It's only asked once: **signing back in is
   just email + password**, since the token already lives on the account.
3. **Home** - paste a GitHub repo URL (or a username to browse their repos),
   with quick links to History and Find Repos. A **Your Repositories**
   panel underneath auto-loads every repo your token can see - private and
   org repos included - the moment Home renders, no extra click needed.
4. **Analyzer** - the existing tabbed dashboard (Overview, Architecture, API,
   **Database**, AST, Repo Structure, History, chat) exactly as before, plus
   a "← Back to Home" link. The Overview tab now also shows a health-score
   trend and (when GitHub commit data is available) an Ownership card; the
   new Database tab covers the ER diagram, system flow diagram, and a plain
   table-list view - see "Major upgrade" in CHANGES.md for what each of
   these does and how they degrade when a repo has nothing to show.

`GET /api/setup/status` reports whether setup has been completed; the
frontend calls it once on load, before checking for a stored login session.

## Database

Storage is **MongoDB**, via the official `mongodb` driver (`db/mongoClient.js`). Point
`MONGODB_URI` at a local `mongod` or a hosted Atlas cluster - see Quick Start above.
Indexes are created automatically on startup (`ensureIndexes()`), so there's no
separate migration step. Five collections:

| Collection | Purpose |
|---|---|
| `users` | Accounts (email + bcrypt password hash) |
| `repositories` | One document per distinct repo ever scanned |
| `scans` | One document per audit run - score, grade, summary, timestamps. Security findings, extracted API endpoints, and detected ORM models are embedded arrays on the scan document itself (`vulnerabilities`, `apiEndpoints`, `databaseModels`) rather than separate collections, since Mongo doesn't need a join table for that |
| `chatMessages` | Chat history, tied to a scan |
| `cloneJobs` | Audit trail of clone attempts (success/failure/timeout), surfaced at `GET /api/clone-jobs` |

Every scan is kept (not overwritten), which is what powers the score-trend sparkline
and scan history. `db/queries.js` is the only file that touches the database directly -
if you'd rather use an ODM (Mongoose) or move to Postgres/MySQL for a real deployment,
that's the one file to change; nothing else in the app talks to Mongo directly.

## API reference

| Route | Notes |
|---|---|
| `GET /api/analyze?url=owner/repo` | Runs (or reuses a cached) scan. `&force=true` bypasses the 10-minute cache. |
| `GET /api/setup/status` | Whether the first-run Setup screen has been completed |
| `POST /api/setup` | `{ jwtSecret?, githubToken? }` - saves into `backend/.env` and applies immediately |
| `GET /api/profile?user=username` | Lists a user/org's repos |
| `POST /api/auth/register` / `/login` | Returns a JWT |
| `GET /api/auth/me` | Current user (requires auth) |
| `GET /api/scans?scope=public\|mine` | Scan history feed |
| `GET /api/scans/:id` | Full report for one past scan |
| `DELETE /api/scans/:id` | Owner-only |
| `GET /api/repositories/:owner/:repo/history` | Score-over-time for one repo |
| `POST /api/chat` | `{ message, scanId }` → streamed SSE response |

Scanning and chat work without logging in; signing in just attributes your scans to
your account so they show up under "My Scans" instead of the public feed.

## Testing

```bash
npm test --prefix backend
```

Covers the input validator (including the exact injection/traversal payloads described
in CHANGES.md) and the health-scoring engine.

## Ideas to take this further

Roughly ordered by effort. Good picks for turning this into a complete capstone/major
project submission:

**Smaller (a few hours each)**
- Pagination on `/api/scans` (currently just `limit`)
- Badge endpoint: `GET /api/badge/:owner/:repo.svg` → embeddable shields.io-style health badge for READMEs
- Compare view: pick two scans of the same repo and diff the health score / vulnerabilities / API surface side by side
- Password reset flow (email token) now that there are real accounts
- Rate-limit response headers surfaced in the UI so people can see how many scans they have left

**Medium**
- Webhooks: register a GitHub webhook so a repo re-scans itself automatically on push, instead of waiting for someone to click a button
- Notifications: email or Slack message when a tracked repo's score drops or a new critical vulnerability appears
- Team/organization accounts: shared scan history and a dashboard across a whole GitHub org
- Swap the local-Ollama chat for a hosted LLM API behind a feature flag, so chat still works when deployed somewhere without a GPU/Ollama install (right now it only works if Ollama is running on the same machine as the backend - fine for local dev, not for a real deployment)
- Redis (or an in-process LRU you already have a start on in `server.js`) for hot scan data, so MongoDB isn't hit on every chat token

**Bigger**
- Multi-language AST support - right now only JavaScript gets a real AST (via acorn); Python/Go/Java would need per-language parsers
- A "trust score" that combines this repo's health score with its dependencies' health scores (recursively scan what it depends on)
- Public API + API keys for programmatic access, with per-key usage tracking in the database
- A proper schema-versioning/migration tool once the document shape stabilizes (e.g. `migrate-mongo`), or a move to Postgres + Prisma/Drizzle for a real deployment - see CHANGES.md for the history of why this project landed on MongoDB with a hand-written data-access layer instead of an ORM

## A note on the AI chat

The chat assistant calls a local **Ollama** instance (`http://localhost:11434`, model
`mistral`) - see `backend/analyzer/chatAgent.js` and `summarizer.js`. Install
[Ollama](https://ollama.com), run `ollama pull mistral`, and keep it running alongside
the backend for AI summaries and chat to work. Without it, CodeAtlas still works fully
(scanning, scoring, history, everything) - the AI-dependent fields just report
themselves as unavailable instead of erroring.
