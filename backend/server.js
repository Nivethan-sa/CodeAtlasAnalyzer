require("./instrument");
const Sentry = require("@sentry/node");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const axios = require("axios");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const { execFile } = require("child_process");
const util = require("util");
const execFileAsync = util.promisify(execFile);
require("dotenv").config();

const analyzeRepository = require("./analyzer");
const { buildCodeSnapshot } = require("./analyzer/codeSnapshot");
const { getRepoInsights } = require("./analyzer/repoInsights");
const askRepoChatbot = require("./analyzer/chatAgent");
const db = require("./db/queries");
const { optionalAuth, requireAuth } = require("./middleware/auth");
const {
  parseGithubRepoInput,
  isSafeGithubUsername,
} = require("./utils/validate");
const { toLongPath, safeRemove } = require("./utils/longPath");
const { upsertEnvValues } = require("./utils/envStore");

const authRoutes = require("./routes/auth");
const setupRoutes = require("./routes/setup");
const { router: scanRoutes, toAnalyzePayload } = require("./routes/scans");
const { generateDiagrams } = require("./analyzer/diagramGenerator");
const repositoryRoutes = require("./routes/repositories");

const IS_PRODUCTION = process.env.NODE_ENV === "production";

if (!process.env.JWT_SECRET && IS_PRODUCTION) {
  // On a real deployment (containers, PaaS) backend/.env is usually
  // ephemeral, so an auto-generated secret would be lost on every restart
  // and sign everyone out. Make the operator set it explicitly.
  console.error(
    "❌ JWT_SECRET is required when NODE_ENV=production. Generate one with:\n" +
      "   node -e \"console.log(require('crypto').randomBytes(48).toString('hex'))\"\n" +
      "   and set it as an environment variable.",
  );
  process.exit(1);
}

if (!process.env.JWT_SECRET) {
  // No JWT_SECRET on disk yet - rather than refusing to start (the old
  // behavior), generate a random one so the server can boot and serve the
  // in-browser Setup screen.
  //
  // This used to live ONLY in process.env (never written to disk), which
  // meant every "Skip for now" click - or any restart before Setup was
  // completed - silently rotated the signing key. Every previously-issued
  // token (and localStorage session) became invalid on the very next
  // restart, which bounced already-logged-in users back to Sign In with a
  // generic "Invalid or expired session" and no explanation - and since
  // `.setup-complete` already existed, the Setup wizard never ran again to
  // let them fix it. Persisting the generated value into backend/.env
  // immediately - the same helper the Setup screen itself uses - closes
  // that gap: the very first boot picks a real secret and it stays stable
  // across restarts from then on, exactly as if the person had pasted one
  // in by hand. It's still fully editable later from Settings, or by hand
  // in backend/.env.
  const generated = crypto.randomBytes(48).toString("hex");
  try {
    upsertEnvValues({ JWT_SECRET: generated });
    console.warn(
      "⚠️  JWT_SECRET was not set in backend/.env - generated one and saved it there automatically.\n" +
        "   Sessions will now survive server restarts. Change it any time from Settings in the app.",
    );
  } catch (error) {
    // Falls back to the old ephemeral (in-memory only) behavior if the
    // directory isn't writable for some reason - still lets the server
    // boot rather than crashing on startup.
    process.env.JWT_SECRET = generated;
    console.warn(
      "⚠️  JWT_SECRET is not set and backend/.env isn't writable (" +
        error.message +
        ") - using a temporary in-memory value for this session only.",
    );
  }
}

const app = express();
const PORT = process.env.PORT || 5001;

// Behind an HTTPS reverse proxy (Caddy, nginx, Render, Railway, ...) the
// real client IP and protocol arrive in X-Forwarded-* headers. Without this,
// every visitor shares the proxy's IP in the rate limiters (one person could
// lock everyone out) and req.secure is always false. TRUST_PROXY = number of
// proxy hops in front of Node (default 1 in production, off in development).
const trustProxyHops = process.env.TRUST_PROXY !== undefined
  ? Number(process.env.TRUST_PROXY)
  : IS_PRODUCTION ? 1 : 0;
if (trustProxyHops) app.set("trust proxy", trustProxyHops);

// Send plain-http visitors to https:// in production (the proxy terminates
// TLS and tells us the original scheme). /api/health stays reachable over
// http for load-balancer health checks. Set FORCE_HTTPS=false to disable.
if (IS_PRODUCTION && process.env.FORCE_HTTPS !== "false") {
  app.use((req, res, next) => {
    if (req.secure || req.path === "/api/health") return next();
    return res.redirect(308, `https://${req.headers.host}${req.originalUrl}`);
  });
}

// --- LAST-RESORT CRASH GUARDS -------------------------------------------
// Everything inside a route handler that's reachable via `await` already
// flows into that route's own try/catch (e.g. /api/analyze's big try block
// around the clone+scan pipeline). But a few things can still throw or
// reject *outside* that path - a background/fire-and-forget promise, a
// synchronous bug in a library callback, a stray `.then()` with no
// `.catch()` - and Node's default behavior for both `uncaughtException` and
// (since Node 15) an unhandled promise rejection is to print a stack trace
// and kill the entire process. That takes down every in-progress scan and
// every other connected user's session along with it, and looks to the
// frontend exactly like "the scan crashed" followed by "now it's asking me
// to sign in again" once the process (or whatever's supervising it, if
// anything) comes back up. Logging and staying alive here doesn't fix
// whatever the underlying bug is, but it turns a full outage into a single
// failed request - which is what should have happened in the first place.
process.on("unhandledRejection", (reason) => {
  Sentry.captureException(reason);
  console.error("⚠️  Unhandled promise rejection (server staying up):", reason);
});
process.on("uncaughtException", (error) => {
  Sentry.captureException(error);
  console.error("⚠️  Uncaught exception (server staying up):", error);
});

// How long a repository's most recent scan is considered "fresh enough"
// to serve straight from the database instead of re-cloning and
// re-scanning. Pass ?force=true to bypass this.
const SCAN_CACHE_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

// Google Sign-In opens a popup that posts the result back to this page.
// Helmet's default Cross-Origin-Opener-Policy ("same-origin") severs that
// channel and the button silently does nothing, so allow popups.
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    // Tell browsers to only ever use https for this host (1 year).
    strictTransportSecurity: IS_PRODUCTION
      ? { maxAge: 31536000, includeSubDomains: true }
      : false,
  }),
);
// The page and API share one origin, so cross-origin access is only needed
// if you host the frontend elsewhere. In production it's off unless you list
// origins in CORS_ORIGIN (comma-separated, e.g. https://app.example.com).
app.use(
  cors(
    IS_PRODUCTION
      ? {
          origin: process.env.CORS_ORIGIN
            ? process.env.CORS_ORIGIN.split(",").map((o) => o.trim())
            : false,
        }
      : undefined,
  ),
);
app.use(express.json());

// Serve the dashboard itself, so `npm start` gives you the whole app
// (frontend + API) on one origin/port - no second dev server, no CORS
// juggling. Visiting http://localhost:5001 loads frontend/index.html.
app.use(
  express.static(path.join(__dirname, "..", "frontend"), {
    // Always revalidate the HTML so a browser never keeps showing an old
    // copy of the page (e.g. the previous Sign-in-first version).
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-cache");
    },
  }),
);

// Generous global limiter just to blunt casual abuse/scripted hammering.
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

// Cloning + scanning a repo is the expensive operation, so it gets its
// own tighter limiter on top of the global one.
const analyzeLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many scans requested. Please wait a few minutes." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many auth attempts. Please wait a few minutes." },
});

app.use("/api/setup", authLimiter, setupRoutes);
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/scans", scanRoutes);
app.use("/api/repositories", repositoryRoutes);

// In-memory cache so a burst of chat messages about the scan we *just*
// computed doesn't each round-trip to the DB. Falls back to a DB fetch
// (via toAnalyzePayload) when the entry isn't cached, e.g. after a
// restart or when chatting about a scan loaded from history.
const recentScanCache = new Map();
// Same idea for the source-code snapshot the chat agent reads (can be large,
// so keep fewer of them in memory; the database is the source of truth).
const recentSourceCache = new Map();
function cacheSource(scanId, snapshot) {
  recentSourceCache.set(scanId, snapshot);
  if (recentSourceCache.size > 10) {
    recentSourceCache.delete(recentSourceCache.keys().next().value);
  }
}
function cacheScan(scanId, payload) {
  recentScanCache.set(scanId, payload);
  if (recentScanCache.size > 200) {
    recentScanCache.delete(recentScanCache.keys().next().value);
  }
}

function readGithubToken(token) {
  return token ? { Authorization: `token ${token}` } : {};
}

/** Prefers the signed-in user's own GitHub token (set at signup or later
 *  from Settings) over the shared server-wide GITHUB_TOKEN, so everyone's
 *  scans use their own identity/rate limit instead of exhausting one
 *  shared token. Falls back to the server-wide token (or none) for
 *  anonymous requests or accounts that never set one. */
async function resolveGithubToken(reqUser) {
  if (reqUser) {
    const fullUser = await db.findUserById(reqUser.id);
    if (fullUser && fullUser.githubToken) return fullUser.githubToken;
  }
  return process.env.GITHUB_TOKEN || null;
}

/** Turns the plain clone_url GitHub's API returns (e.g.
 *  "https://github.com/owner/repo.git") into one `git clone` can actually
 *  authenticate with, by embedding the resolved token as HTTP Basic
 *  credentials ("x-access-token" is GitHub's documented placeholder
 *  username for token-based git auth - the token itself is what's
 *  checked, not the username). Without this, the token was only ever
 *  used for the metadata/branches/commits REST calls above - `git clone`
 *  itself always hit the anonymous URL, so it worked for public repos but
 *  would silently 401/404 on any private repo even though the user had
 *  supplied a perfectly valid token. With no token at all, the URL is
 *  returned unchanged: anonymous cloning of public repos still works
 *  exactly as before. */
function withCloneCredentials(cloneUrl, token) {
  if (!token) return cloneUrl;
  const url = new URL(cloneUrl);
  url.username = "x-access-token";
  url.password = token;
  return url.toString();
}

/** Strips any embedded "user:token@" credentials out of a URL before the
 *  string is logged to the console or persisted to the clone_jobs table -
 *  git's own error messages (e.g. "fatal: repository '<url>' not found")
 *  echo the URL it was given verbatim, and that URL now carries the raw
 *  token when one was supplied. */
function redactCloneCredentials(message, token) {
  if (!message || !token) return message;
  return message.split(token).join("***");
}

// --- TRANSIENT NETWORK RETRY ---------------------------------------------
// Errors like ECONNRESET, ETIMEDOUT, ECONNABORTED, and a failed TCP connect
// to github.com:443 are almost always momentary - a dropped packet, a proxy
// hiccup, a brief GitHub blip - not a real answer about the repo/token/user.
// Previously a single one of these killed the entire request (or, in the
// batch profile scanner, that one repo) even though trying again a second
// later would very likely succeed. This wraps any such call with a few
// quick retries before giving up for real.
const TRANSIENT_ERROR_CODES = new Set([
  "ECONNRESET",
  "ETIMEDOUT",
  "ECONNABORTED",
  "ECONNREFUSED",
  "EAI_AGAIN",
  "ENETUNREACH",
  "EPIPE",
]);

/** True for connection-level failures (never got an HTTP response at all,
 *  or a git process that died to a network signal) as opposed to GitHub
 *  actually answering with a 401/403/404 - those are real answers and
 *  should never be retried. */
function isTransientNetworkError(error) {
  if (!error) return false;
  // axios: no `.response` + a `.code` means the request never reached the
  // server (DNS, refused connection, reset, timeout) - not an HTTP error.
  if (!error.response && error.code && TRANSIENT_ERROR_CODES.has(error.code)) {
    return true;
  }
  // execFile (git clone): the underlying git process's stderr carries the
  // real reason, since Node's own `.code` for a spawned child is just its
  // exit code, not a network errno.
  const text = String(error.message || "");
  return (
    /Failed to connect to .* port \d+/i.test(text) ||
    /Could not resolve host/i.test(text) ||
    /connection (was )?reset/i.test(text) ||
    /connection timed out/i.test(text) ||
    TRANSIENT_ERROR_CODES.has(error.code)
  );
}

/** Retries `fn` up to `attempts` times with exponential backoff (1s, 2s,
 *  4s, ...), but only when the failure looks transient/network-level per
 *  `isTransientNetworkError`. Any other error (auth, 404, rate limit,
 *  validation, etc.) rethrows immediately on the first try - retrying
 *  those would just waste time reproducing the same real answer. `label`
 *  is purely for the retry log line, so failures are traceable to which
 *  step they happened in. */
async function withRetry(
  fn,
  { attempts = 3, baseDelayMs = 1000, label = "request" } = {},
) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const isLastAttempt = attempt === attempts;
      if (!isTransientNetworkError(error) || isLastAttempt) {
        throw error;
      }
      const delayMs = baseDelayMs * 2 ** (attempt - 1);
      console.warn(
        `⚠️  Transient network error on ${label} (attempt ${attempt}/${attempts}: ${error.code || error.message}) - retrying in ${delayMs}ms...`,
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

// --- ROUTE: THE SCANNER -------------------------------------------------
app.get("/api/analyze", analyzeLimiter, optionalAuth, async (req, res) => {
  const rawInput = req.query.url;
  let tempFolder = "";

  if (!rawInput) {
    return res.status(400).json({ error: "Please provide a GitHub URL" });
  }

  const parsed = parseGithubRepoInput(rawInput);
  if (!parsed) {
    return res.status(400).json({
      error:
        "That doesn't look like a valid GitHub repository. Use a full URL (https://github.com/owner/repo) or owner/repo.",
    });
  }
  const { owner: username, repo: repoName } = parsed;
  const fullName = `${username}/${repoName}`;
  const force = req.query.force === "true";

  try {
    // --- Cache fast-path: served straight from the database ---------
    if (!force) {
      const lastScan = await db.findLatestScanForRepository(fullName);
      if (
        lastScan &&
        Date.now() - lastScan.createdAt.getTime() < SCAN_CACHE_WINDOW_MS
      ) {
        const payload = toAnalyzePayload(lastScan);
        cacheScan(lastScan.id, payload);
        return res.status(200).json({ ...payload, cached: true });
      }
    }

    console.log(`\n1. Fetching metadata for ${username}/${repoName}...`);
    const githubApiUrl = `https://api.github.com/repos/${username}/${repoName}`;
    const githubToken = await resolveGithubToken(req.user);

    const response = await withRetry(
      () =>
        axios.get(githubApiUrl, {
          headers: {
            ...readGithubToken(githubToken),
            "User-Agent": "CodeAtlas-Analyzer",
          },
          timeout: 15000,
        }),
      { label: `metadata fetch for ${fullName}` },
    );

    console.log(`2. Cloning repository locally...`);
    // Public repos clone fine anonymously either way; private repos need
    // the resolved token turned into actual git credentials here, since
    // the token above was only ever attached to the REST API calls.
    const cloneUrl = withCloneCredentials(response.data.clone_url, githubToken);
    // Cloned into the OS temp dir with a short, random suffix - NOT nested
    // under __dirname. On Windows, __dirname can itself already be deep
    // (e.g. "C:\Users\<name>\Downloads\New folder (2)\CodeAtlas\backend"),
    // and combined with a repo that has long nested paths (Java/Maven
    // projects especially - "src/main/java/io/foo/bar/baz/qux/..." adds up
    // fast), the total path blows past Windows' MAX_PATH and `git clone`
    // fails checkout with "Filename too long". Using os.tmpdir() removes
    // most of that prefix, and a short random id (instead of embedding the
    // full owner/repo name + timestamp) trims it further. What's left of
    // the limit is additionally covered by `-c core.longpaths=true` below
    // and the long-path-safe cleanup at the end of this handler.
    const tempSlug = crypto.randomBytes(6).toString("hex");
    tempFolder = path.join(os.tmpdir(), "codeatlas-scans", tempSlug);

    fs.mkdirSync(path.dirname(tempFolder), { recursive: true });
    await safeRemove(tempFolder, { label: `stale temp clone for ${fullName}` });

    // execFile (async, no shell) instead of execSync(`...`) - arguments are
    // passed as a literal array, so nothing in cloneUrl/tempFolder can
    // break out into a second shell command. Using the async form (rather
    // than execFileSync) matters here: execFileSync blocks Node's single
    // event loop for the entire duration of the clone, which freezes the
    // whole server - every other request, including other people's scans
    // and simple health checks, just hangs until the clone finishes. A hard
    // `timeout` also means one slow/huge/stalled remote can't wedge a scan
    // forever - it gets killed and reported as a clear error instead.
    // `-c core.longpaths=true` tells Git for Windows to use the `\\?\`
    // long-path API during checkout instead of the classic Win32 one, so
    // deeply-nested repo paths (again, Java/Maven's specialty) don't fail
    // with "Filename too long" even after the tempFolder shortening above.
    // It's a no-op (harmless) on macOS/Linux, which never had this limit.
    const CLONE_TIMEOUT_MS = 60 * 1000;
    const cloneJobId = await db.createCloneJob({
      repositoryFullName: fullName,
      tempPath: tempFolder,
    });
    const cloneStartedAt = Date.now();
    try {
      await withRetry(
        async () => {
          // A previous attempt in this same retry loop may have left a
          // partial checkout behind (git aborted mid-clone on the reset/
          // timeout) - `git clone` refuses to clone into a non-empty
          // directory, so that partial folder has to go before trying
          // again, not just on the very first attempt.
          await safeRemove(tempFolder, {
            label: `partial clone retry for ${fullName}`,
          });
          await execFileAsync(
            "git",
            [
              "-c",
              "core.longpaths=true",
              "clone",
              "--depth",
              "1",
              "--single-branch",
              cloneUrl,
              tempFolder,
            ],
            { timeout: CLONE_TIMEOUT_MS, maxBuffer: 1024 * 1024 * 20 },
          );
        },
        { label: `git clone of ${fullName}` },
      );
      await db.finishCloneJob(cloneJobId, {
        status: "success",
        durationMs: Date.now() - cloneStartedAt,
      });
    } catch (cloneError) {
      const safeMessage = redactCloneCredentials(
        cloneError.message,
        githubToken,
      );
      const timedOut = cloneError.killed || cloneError.signal === "SIGTERM";
      const pathTooLong = /filename too long|name too long|ENAMETOOLONG/i.test(
        cloneError.message || "",
      );
      // The metadata call above already blocks most private-repo access
      // (GitHub answers those with a 404 to keep them from being
      // enumerated), but a repo can still flip from public to private (or
      // a token can lose access) between that call and this clone, or the
      // token simply may not carry the `repo` scope private clones need
      // even though it could read public metadata. Either way, git's own
      // "not found"/"authentication failed" text is what actually
      // surfaces that, so it's worth telling apart from a generic clone
      // failure.
      const authFailed =
        /authentication failed|repository not found|could not read username/i.test(
          cloneError.message || "",
        );
      await db.finishCloneJob(cloneJobId, {
        status: timedOut ? "timeout" : "failed",
        errorMessage: safeMessage,
        durationMs: Date.now() - cloneStartedAt,
      });
      if (timedOut) {
        return res.status(504).json({
          error:
            "Cloning this repository took too long and was aborted. It may be unusually large - try again or pick a smaller repo.",
        });
      }
      if (pathTooLong) {
        return res.status(422).json({
          error:
            "This repository has file paths too long for Windows to check out (common with deeply-nested Java/Maven projects). " +
            "We already clone to a short temp path and enable Git's long-path support, but this repo's paths exceed even that. " +
            "Try enabling Windows long-path support system-wide (Local Group Policy / registry `LongPathsEnabled`) and re-running, " +
            "or run `git config --system core.longpaths true` once, then retry.",
        });
      }
      if (authFailed) {
        return res.status(403).json({
          error: githubToken
            ? "Could not clone this repository with the configured GitHub token. If it's private, make sure the token has 'repo' scope (or, for a fine-grained token, access to this repository) and hasn't expired."
            : "This repository could not be cloned anonymously. If it's private, add a GitHub token (Settings, or at signup) with access to it.",
        });
      }
      cloneError.message = safeMessage;
      throw cloneError;
    }

    let commitSha = null;
    try {
      const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
        cwd: tempFolder,
      });
      commitSha = stdout.trim();
    } catch {
      // Non-fatal - just means we won't be able to show which commit was audited.
    }

    console.log(`3. Analyzing repository...`);
    const [analysisResult, repoInsights] = await Promise.all([
      analyzeRepository(tempFolder, repoName),
      getRepoInsights({
        owner: username,
        repo: repoName,
        headers: {
          ...readGithubToken(githubToken),
          "User-Agent": "CodeAtlas-Analyzer",
        },
        defaultBranch: response.data.default_branch,
        repoApiData: response.data,
      }),
    ]);
    analysisResult.analysis.branches = repoInsights.branches;
    analysisResult.analysis.branch_hierarchy = repoInsights.branch_hierarchy;
    analysisResult.analysis.commits = repoInsights.commits;
    analysisResult.analysis.pull_requests = repoInsights.pull_requests;
    analysisResult.analysis.repo_metadata = repoInsights.metadata;
    analysisResult.analysis.contributors = repoInsights.contributors;

    // Read the real source code now - the clone is deleted in `finally`.
    // This is what lets the chat agent answer questions about the actual
    // code. Never allowed to fail the scan.
    let codeSnapshot = null;
    try {
      codeSnapshot = buildCodeSnapshot(tempFolder);
      console.log(
        `   Code snapshot: ${codeSnapshot.includedFiles}/${codeSnapshot.totalFiles} files, ${codeSnapshot.totalChars} chars` +
          (codeSnapshot.truncated ? " (truncated)" : ""),
      );
    } catch (snapshotError) {
      Sentry.captureException(snapshotError);
      console.warn("⚠️ Could not build code snapshot:", snapshotError.message);
    }

    console.log(`4. Analysis complete. Persisting to database...`);

    const repository = await db.upsertRepository({
      owner: username,
      name: repoName,
      fullName,
      htmlUrl: response.data.html_url,
      description: analysisResult.description,
      primaryLanguage: response.data.language || null,
    });

    const scan = await db.createScan({
      repositoryId: repository.id,
      userId: req.user ? req.user.id : null,
      commitSha,
      filesScanned: analysisResult.analysis.files,
      healthScore: analysisResult.health_audit.score,
      healthGrade: analysisResult.health_audit.grade,
      languages: JSON.stringify(analysisResult.analysis.languages),
      frameworks: JSON.stringify(analysisResult.analysis.frameworks),
      strengths: JSON.stringify(analysisResult.health_audit.strengths),
      warnings: JSON.stringify(analysisResult.health_audit.warnings),
      basicSummary: analysisResult.analysis.basic_summary,
      businessLogic: analysisResult.analysis.business_logic,
      astTargetFile: analysisResult.analysis.ast_structure?.target_file || null,
      astTree: analysisResult.analysis.ast_structure?.tree
        ? JSON.stringify(analysisResult.analysis.ast_structure.tree)
        : null,
      scannedFiles: JSON.stringify(analysisResult.analysis.scanned_files || []),
      classes: JSON.stringify(
        analysisResult.analysis.architecture_symbols?.classes || [],
      ),
      functions: JSON.stringify(
        analysisResult.analysis.architecture_symbols?.functions || [],
      ),
      vulnerabilities: analysisResult.analysis.security_vulnerabilities,
      apiEndpoints: analysisResult.analysis.api_endpoints,
      databaseModels: analysisResult.analysis.database_tables.map((t) => ({
        ormType: t.database_type,
        tableName: t.table_name,
        fields: t.fields || [],
        relationships: t.relationships || [],
      })),
      repoTree: JSON.stringify(analysisResult.analysis.repo_tree || null),
      branches: JSON.stringify(analysisResult.analysis.branches || null),
      branchHierarchy: JSON.stringify(
        analysisResult.analysis.branch_hierarchy || null,
      ),
      commits: JSON.stringify(analysisResult.analysis.commits || null),
      pullRequests: JSON.stringify(
        analysisResult.analysis.pull_requests || null,
      ),
      repoMetadata: JSON.stringify(
        analysisResult.analysis.repo_metadata || null,
      ),
      contributors: JSON.stringify(
        analysisResult.analysis.contributors || null,
      ),
      callGraph: JSON.stringify(analysisResult.analysis.call_graph || []),
    });

    if (codeSnapshot && codeSnapshot.files.length > 0) {
      try {
        await db.saveScanSource(scan.id, codeSnapshot);
        cacheSource(scan.id, codeSnapshot);
      } catch (sourceError) {
        Sentry.captureException(sourceError);
        console.warn("⚠️ Could not save code snapshot:", sourceError.message);
      }
    }

    const payload = toAnalyzePayload(scan);
    cacheScan(scan.id, payload);

    res.status(200).json(payload);
  } catch (error) {
    if (error.response && error.response.status === 401) {
      console.error("❌ GitHub API Error: 401 Unauthorized.");
      return res
        .status(401)
        .json({ error: "Authentication failed. Check GitHub Token." });
    }
    if (error.response && error.response.status === 404) {
      return res.status(404).json({ error: "Repository not found." });
    }
    if (
      error.response &&
      error.response.status === 403 &&
      error.response.headers?.["x-ratelimit-remaining"] === "0"
    ) {
      const resetAt = error.response.headers["x-ratelimit-reset"];
      const resetMsg = resetAt
        ? ` It resets at ${new Date(parseInt(resetAt, 10) * 1000).toLocaleTimeString()}.`
        : "";
      console.error("❌ GitHub API Error: rate limit exceeded.");
      return res.status(429).json({
        error: `GitHub API rate limit exceeded.${resetMsg} Set a GITHUB_TOKEN in backend/.env to raise this limit from 60 to 5,000 requests/hour.`,
      });
    }
    Sentry.captureException(error);
    console.error("❌ Error processing repository:", error.message);
    res.status(500).json({ error: "Failed to process repository." });
  } finally {
    if (tempFolder) {
      console.log(`5. Cleaning up temporary files...`);
      // safeRemove never throws - a cleanup hiccup (a lingering file lock,
      // a path Windows still can't quite resolve) is logged and left for
      // next time, not allowed to crash this handler or mask whatever
      // response was already sent above.
      await safeRemove(tempFolder, { label: `temp clone for ${fullName}` });
    }
  }
});

// --- ROUTE: THE PROFILE BATCH SCANNER -----------------------------------
app.get("/api/profile", optionalAuth, async (req, res) => {
  const username = req.query.user;

  if (!username || !isSafeGithubUsername(username)) {
    return res.status(400).json({
      error: "Please provide a valid GitHub username or organization.",
    });
  }

  try {
    console.log(
      `\n🔍 Fetching entire repository list for user: ${username}...`,
    );
    const githubToken = await resolveGithubToken(req.user);

    // GitHub's public `/users/:username/repos` endpoint only ever returns
    // *public* repositories - no token attached to the request changes
    // that, it's simply not what that endpoint is for. Seeing your own
    // private and org repos requires the authenticated `/user/repos`
    // endpoint instead, which GitHub only lets you use for yourself (there's
    // no way to list another person's private repos, token or not, and
    // rightly so). So this only switches endpoints when the signed-in
    // user has their own token on file *and* is asking about their own
    // GitHub username - anyone else's profile still goes through the
    // public endpoint exactly as before.
    let ownRepoMode = false;
    if (req.user) {
      const fullUser = await db.findUserById(req.user.id);
      if (
        fullUser?.githubToken &&
        fullUser.githubUsername &&
        fullUser.githubUsername.toLowerCase() === username.toLowerCase()
      ) {
        ownRepoMode = true;
      }
    }

    const ownRepoUrl = `https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member`;
    const publicRepoUrl = `https://api.github.com/users/${username}/repos?per_page=100&sort=updated`;
    // Without an explicit timeout, a network hiccup reaching GitHub (a
    // flaky connection, VPN, or restrictive firewall/proxy - common on
    // locked-down corporate or Windows setups) can hang for a very long
    // time before finally failing with something like
    // "connect ETIMEDOUT 20.207.73.85:443" - which used to come back as a
    // generic, unhelpful 500 with no explanation.
    const GITHUB_REQUEST_TIMEOUT_MS = 20000;

    let response;
    let usedOwnRepoMode = ownRepoMode;
    // Set only when we deliberately fell back from the private listing to
    // the public one - lets the frontend explain *why* private repos are
    // missing instead of the person just quietly seeing fewer repos than
    // expected and assuming the feature is broken.
    let privateAccessError = null;

    try {
      response = await withRetry(
        () =>
          axios.get(ownRepoMode ? ownRepoUrl : publicRepoUrl, {
            headers: {
              ...readGithubToken(githubToken),
              "User-Agent": "CodeAtlas-Batch-Scanner",
            },
            timeout: GITHUB_REQUEST_TIMEOUT_MS,
          }),
        { label: `repo list fetch for ${username}` },
      );
    } catch (error) {
      const status = error.response?.status;
      const isRateLimited =
        error.response?.headers?.["x-ratelimit-remaining"] === "0";
      // Axios sets `.code` (not `.response`) for connection-level failures
      // rather than an actual HTTP response from GitHub - a timed-out
      // handshake, DNS failure, connection reset, etc. This is a server
      // network problem, not a bad token, so it gets its own message
      // rather than being lumped in with "token rejected."
      const isNetworkError = !error.response && Boolean(error.code);

      // A saved token that GitHub itself now rejects - expired, revoked, or
      // (very commonly) missing the `repo` scope needed to list private
      // repos - used to fail the *entire* profile view with a generic
      // error, which looked indistinguishable from "private repos just
      // aren't showing up." Same for a network-level failure reaching
      // GitHub at all. Instead, retry anonymously against the public
      // endpoint so the person still sees their public repos, and say
      // plainly why the private ones didn't come through.
      if (
        ownRepoMode &&
        (((status === 401 || status === 403) && !isRateLimited) ||
          isNetworkError)
      ) {
        console.warn(
          `⚠️  Own-repo GitHub request failed for ${username} (${isNetworkError ? `network error: ${error.code}` : `status ${status}`}) - falling back to public listing.`,
        );
        usedOwnRepoMode = false;
        privateAccessError = isNetworkError
          ? `Could not reach GitHub to check your private repositories (${error.code === "ECONNABORTED" ? "request timed out" : error.code}) - showing public repositories only. This looks like a network/firewall/proxy issue on this server rather than a problem with your token - try again in a moment.`
          : status === 401
            ? 'Your saved GitHub token was rejected (expired or revoked) - showing public repositories only. Reconnect it via "Connect GitHub".'
            : 'Your saved GitHub token doesn\'t have permission to list private repositories (needs the "repo" scope) - showing public repositories only.';
        try {
          response = await withRetry(
            () =>
              axios.get(publicRepoUrl, {
                headers: { "User-Agent": "CodeAtlas-Batch-Scanner" },
                timeout: GITHUB_REQUEST_TIMEOUT_MS,
              }),
            { label: `public repo list fallback for ${username}` },
          );
        } catch (fallbackError) {
          // GitHub is genuinely unreachable right now (not just the
          // authenticated call) - nothing left to fall back to.
          throw fallbackError;
        }
      } else {
        throw error;
      }
    }

    const allRepos = response.data.map((repo) => ({
      name: repo.name,
      full_url: repo.html_url,
      description: repo.description || "No description provided.",
      primary_language: repo.language || "Mixed/Unknown",
      stars: repo.stargazers_count,
      size_kb: repo.size,
      last_updated: repo.updated_at,
      private: Boolean(repo.private),
    }));

    console.log(
      `✅ Successfully found ${allRepos.length} repositories for ${username}.`,
    );

    res.status(200).json({
      owner: username,
      total_repositories: allRepos.length,
      repositories: allRepos,
      // Lets the frontend show "including private repos" only when that's
      // actually true, instead of assuming based on whether a token exists.
      includes_private: usedOwnRepoMode,
      private_access_error: privateAccessError,
    });
  } catch (error) {
    console.error("❌ Profile Fetch Error:", error.message);
    if (error.response && error.response.status === 404) {
      return res
        .status(404)
        .json({ error: "GitHub user or organization not found." });
    }
    if (
      error.response &&
      error.response.status === 403 &&
      error.response.headers?.["x-ratelimit-remaining"] === "0"
    ) {
      const resetAt = error.response.headers["x-ratelimit-reset"];
      const resetMsg = resetAt
        ? ` It resets at ${new Date(parseInt(resetAt, 10) * 1000).toLocaleTimeString()}.`
        : "";
      return res.status(429).json({
        error: `GitHub API rate limit exceeded.${resetMsg} Set a GITHUB_TOKEN in backend/.env to raise this limit from 60 to 5,000 requests/hour.`,
      });
    }
    // No `error.response` + an error `.code` means the request never got
    // an answer from GitHub at all - DNS failure, connection refused,
    // handshake timeout, etc. - as opposed to GitHub answering with an
    // error. Worth telling apart from a generic failure: this points at
    // this server's own network/firewall/proxy path to GitHub, not
    // anything wrong with the repo, the account, or the token.
    if (!error.response && error.code) {
      return res.status(503).json({
        error: `Could not reach GitHub's API (${error.code === "ECONNABORTED" ? "request timed out" : error.code}). This usually means this server's network can't reach api.github.com right now - check its internet connection, VPN, or firewall/proxy settings, then try again.`,
      });
    }
    Sentry.captureException(error);
    res.status(500).json({ error: "Failed to fetch profile repositories." });
  }
});

// --- ROUTE: THE CHATBOT --------------------------------------------------
// Previously this endpoint ignored the scanned repository entirely and
// just forwarded the raw message to Ollama - the model had no idea what
// repo you were even asking about. It's now tied to a specific scanId,
// loads that scan's real context (from cache or the database), and
// saves both sides of the conversation.
app.post("/api/chat", optionalAuth, async (req, res) => {
  const { message, scanId } = req.body || {};

  if (!message || typeof message !== "string") {
    return res.status(400).json({ error: "Message is required." });
  }
  if (!scanId) {
    return res
      .status(400)
      .json({ error: "scanId is required - run a scan first." });
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const send = (event) => res.write(`data: ${JSON.stringify(event)}\n\n`);

  try {
    let context = recentScanCache.get(scanId);
    if (!context) {
      const scan = await db.findScanById(scanId);
      if (!scan) {
        send({ error: "Unknown scanId - run a new scan first." });
        return res.end();
      }
      context = toAnalyzePayload(scan);
      cacheScan(scanId, context);
    }

    // The scan's real source code (saved at scan time), cached in memory.
    let sourceSnapshot = recentSourceCache.get(scanId);
    if (!sourceSnapshot) {
      sourceSnapshot = await db.findScanSource(scanId);
      if (sourceSnapshot) cacheSource(scanId, sourceSnapshot);
    }

    // Earlier messages so follow-up questions make sense. Only for signed-in
    // users - anonymous chats share one null user id, so they'd see each other's.
    // Must be loaded BEFORE saving the new message below (no duplicate).
    const history = req.user
      ? await db.listRecentChatMessages(scanId, req.user.id, 10)
      : [];

    await db.createChatMessage({
      scanId,
      userId: req.user ? req.user.id : null,
      role: "user",
      content: message,
    });

    const fullReply = await askRepoChatbot(
      message,
      context,
      (token) => {
        send({ token });
      },
      { sourceSnapshot, history },
    );

    await db.createChatMessage({
      scanId,
      userId: req.user ? req.user.id : null,
      role: "assistant",
      content: fullReply,
    });

    send({ done: true });
    res.end();
  } catch (error) {
    Sentry.captureException(error);
    console.error("❌ Chat error:", error.message);
    send({ error: "Failed to reach the AI assistant." });
    res.end();
  }
});

// --- ROUTE: AI-GENERATED DIAGRAMS ------------------------------------------
// Gemini writes a Python (graphviz) script for the ER diagram and another for
// the system flow; each script is validated and run in an isolated Python
// process (utils/pythonDiagram.js) and the resulting DOT is returned for the
// browser to draw. Results are cached per scan so reopening the tab (or
// several people opening the same public scan) doesn't re-bill Gemini.
const diagramLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many diagram requests. Please wait a few minutes." },
});
const diagramCache = new Map();
const diagramInFlight = new Map();

app.post("/api/diagrams", diagramLimiter, optionalAuth, async (req, res) => {
  const { scanId, refresh } = req.body || {};
  if (!scanId || typeof scanId !== "string") {
    return res.status(400).json({ error: "scanId is required - run a scan first." });
  }
  try {
    let context = recentScanCache.get(scanId);
    if (!context) {
      const scan = await db.findScanById(scanId);
      if (!scan) return res.status(404).json({ error: "Unknown scanId - run a new scan first." });
      context = toAnalyzePayload(scan);
      cacheScan(scanId, context);
    }

    if (!refresh && diagramCache.has(scanId)) {
      return res.json({ ...diagramCache.get(scanId), cached: true });
    }
    // Two quick clicks on "Regenerate" should share one Gemini call, not two.
    if (!diagramInFlight.has(scanId)) {
      diagramInFlight.set(
        scanId,
        generateDiagrams(context.analysis || {}).finally(() => diagramInFlight.delete(scanId)),
      );
    }
    const result = await diagramInFlight.get(scanId);

    // Only cache a result where at least one diagram worked - a transient
    // Gemini/quota failure shouldn't stick around.
    if (result.er.dot || result.flow.dot) {
      diagramCache.set(scanId, result);
      if (diagramCache.size > 50) diagramCache.delete(diagramCache.keys().next().value);
    }
    res.json({ ...result, cached: false });
  } catch (error) {
    Sentry.captureException(error);
    console.error("❌ Diagram error:", error.message);
    res.status(500).json({ error: "Failed to generate the diagrams." });
  }
});

app.get("/api/health", (req, res) => res.json({ status: "ok" }));

// --- ROUTE: CLONE JOB HISTORY (temp_repos audit trail) -------------------
// Requires sign-in since this exposes internal file paths and raw error
// messages - not secret, but not something to leave wide open either.
// Lets you see, after the fact, whether a scan's clone step succeeded,
// failed, or timed out and how long it took - useful for diagnosing a
// "stuck cloning" report without needing live server log access.
app.get("/api/clone-jobs", requireAuth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
  const repo = req.query.repo || null;
  try {
    const clone_jobs = await db.listCloneJobs({
      limit,
      repositoryFullName: repo,
    });
    res.json({ clone_jobs });
  } catch (error) {
    Sentry.captureException(error);
    console.error("❌ Clone job history error:", error.message);
    res.status(500).json({ error: "Failed to load clone job history." });
  }
});
Sentry.setupExpressErrorHandler(app);

// Mongo's connection is asynchronous (a real network handshake, unlike
// the old node:sqlite file which was ready the instant it was required),
// so the server only starts accepting requests once it's confirmed - a
// request landing before that would just throw "not connected yet" from
// db/mongoClient.js's getDb(). If MongoDB is unreachable, this exits with
// a clear message instead of the app silently serving broken responses.
async function start() {
  try {
    await db.connect();
  } catch (error) {
    console.error("❌ Failed to connect to MongoDB:", error.message);
    console.error(
      "   Check MONGODB_URI in backend/.env and that your MongoDB server/Atlas cluster is reachable.",
    );
    process.exit(1);
  }

  app.listen(PORT, () =>
    console.log(`\n CodeAtlas API is running on http://localhost:${PORT}`),
  );
}

start();
