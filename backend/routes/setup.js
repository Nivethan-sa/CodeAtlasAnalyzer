const express = require("express");
const fs = require("fs");
const path = require("path");
const { upsertEnvValues } = require("../utils/envStore");
const { verifyGithubToken, getRateLimit } = require("../utils/githubToken");

const router = express.Router();

// A tiny marker file (not the .env itself) that just records "the user has
// been through the Setup screen at least once" - so returning users go
// straight to login instead of seeing the wizard every time, even if they
// clicked "Skip for now" and never set real values.
const STATE_PATH = path.join(__dirname, "..", ".setup-complete");

// These endpoints change server-wide secrets and are not tied to a login, so
// on a public (production) deployment they are OFF unless ALLOW_SETUP=true.
// Configure JWT_SECRET / GITHUB_TOKEN with environment variables instead.
function setupDisabled() {
  return process.env.NODE_ENV === "production" && process.env.ALLOW_SETUP !== "true";
}

function isSetupComplete() {
  return fs.existsSync(STATE_PATH);
}

// --- GET /api/setup/status ------------------------------------------------
// Also reports the server-wide token's current GitHub API rate-limit
// bucket (60/hour unauthenticated, 5,000/hour with a valid token), so the
// Setup/Settings screen can show "you have N requests left" instead of
// someone only discovering the limit exists after a scan 429s. This is
// always the *server-wide* GITHUB_TOKEN's bucket - status is served before
// login exists, so there's no per-user token to check yet.
router.get("/status", async (req, res) => {
  const rateLimit = await getRateLimit(process.env.GITHUB_TOKEN || null);

  res.json({
    completed: isSetupComplete(),
    setupDisabled: setupDisabled(),
    githubTokenConfigured: Boolean(process.env.GITHUB_TOKEN),
    jwtSecretConfigured: Boolean(process.env.JWT_SECRET),
    rateLimit,
  });
});

// --- POST /api/setup -------------------------------------------------------
// Body: { jwtSecret?: string, githubToken?: string }. Both optional - an
// empty body just marks setup as "seen" (used by the "Skip for now" link),
// which is fine because server.js always guarantees SOME JWT_SECRET exists
// (falling back to an ephemeral generated one) before this route can even
// be reached.
router.post("/", async (req, res) => {
  if (setupDisabled()) {
    return res.status(403).json({
      error: "Server keys are set with environment variables on this deployment.",
    });
  }
  const { jwtSecret, githubToken } = req.body || {};

  if (jwtSecret !== undefined && jwtSecret !== "") {
    if (typeof jwtSecret !== "string" || jwtSecret.length < 32) {
      return res.status(400).json({
        error: "JWT secret must be at least 32 characters - use the Generate button.",
      });
    }
  }

  // Verify a newly-supplied token actually works against GitHub before
  // writing it to disk, instead of only discovering it's bad the next time
  // someone tries to scan a private repo. An explicit empty string (used to
  // *clear* a previously-set token) is left alone - there's nothing to
  // verify. `valid === null` means GitHub couldn't be reached at all (not
  // that the token is bad), so that case is let through rather than
  // blocking the save on a network hiccup.
  let tokenInfo = null;
  if (typeof githubToken === "string" && githubToken.trim()) {
    tokenInfo = await verifyGithubToken(githubToken);
    if (tokenInfo.valid === false) {
      return res.status(400).json({ error: tokenInfo.reason });
    }
  }

  const updates = {};
  if (jwtSecret) updates.JWT_SECRET = jwtSecret;
  // Allow an explicit empty string to clear a previously-set token, but
  // don't touch GITHUB_TOKEN if the field wasn't sent at all.
  if (typeof githubToken === "string") updates.GITHUB_TOKEN = githubToken;

  try {
    if (Object.keys(updates).length) upsertEnvValues(updates);
    fs.writeFileSync(STATE_PATH, new Date().toISOString());
    res.json({
      completed: true,
      // Only present when a token was submitted this call - tells the
      // frontend who it belongs to and whether verification could even run.
      githubTokenVerification: tokenInfo
        ? {
            verified: tokenInfo.valid === true,
            login: tokenInfo.login || null,
            scopes: tokenInfo.scopes || [],
            note: tokenInfo.valid === null ? tokenInfo.reason : null,
          }
        : null,
    });
  } catch (error) {
    console.error("❌ Setup error:", error.message);
    res.status(500).json({ error: "Failed to save setup values." });
  }
});

module.exports = router;
