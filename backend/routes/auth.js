const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../db/queries");
const { requireAuth } = require("../middleware/auth");
const { computeSigningKey } = require("../utils/jwtKey");
const { isSafeGithubUsername } = require("../utils/validate");
const { verifyGithubToken } = require("../utils/githubToken");
const { verifyGoogleCredential, signInWithGoogleProfile, getGoogleClientId } = require("../utils/googleAuth");

const router = express.Router();

const TOKEN_TTL = "7d";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Loose sanity check, not a hard whitelist - GitHub's token formats have
// changed over time (classic ghp_..., fine-grained github_pat_...).
const TOKEN_RE = /^[A-Za-z0-9_.\-]{20,255}$/;

// Accepts a bare username ("octocat") or a full profile URL
// ("https://github.com/octocat") and returns just the username.
function extractGithubUsername(input) {
  if (!input || typeof input !== "string") return null;
  const bare = input.trim().replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/\/+$/, "");
  return isSafeGithubUsername(bare) ? bare : null;
}

// Every token is signed with THIS user's own derived key (see
// utils/jwtKey.js), not one secret shared by every account.
function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, computeSigningKey(user), {
    expiresIn: TOKEN_TTL,
  });
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    githubUsername: user.githubUsername || null,
    // Never the token itself - just whether one is on file, so the
    // frontend can show "GitHub connected" without exposing the value.
    githubTokenSet: Boolean(user.githubToken),
    // Whether this account signs in with Google (and so has no password).
    googleLinked: Boolean(user.googleId),
    avatarUrl: user.avatarUrl || null,
  };
}

// Accounts created before per-user signing keys existed won't have a
// jwtSecret yet - generate one on the fly on next login rather than
// leaving them permanently unable to sign in.
async function ensureSigningKey(user) {
  if (user.jwtSecret) return user;
  return db.regenerateUserJwtSecret(user.id);
}

// --- POST /api/auth/register ------------------------------------------
// Collects the account's own GitHub token (+ optional username) right at
// signup - required, not optional. Two reasons this is enforced here
// rather than left as a nice-to-have:
//   1. Every scan needs *some* GitHub identity to get useful rate limits
//      and to ever see private/org repos - an account with no token on
//      file just quietly falls back to the 60-req/hour anonymous limit
//      (or the server-wide GITHUB_TOKEN, if the operator happened to set
//      one) with no obvious explanation, which looked like "the app keeps
//      asking me for a token" every time that fallback wasn't enough.
//   2. It only needs to be asked once. The token lives on the account from
//      here on (see publicUser().githubTokenSet below), so signing back in
//      later is just email + password - login intentionally does NOT take
//      a githubToken param at all, so there's nothing to re-enter.
router.post("/register", async (req, res) => {
  try {
    const { email, password, username, githubToken, githubUsername } = req.body || {};

    if (!email || !EMAIL_RE.test(email)) {
      return res.status(400).json({ error: "A valid email is required." });
    }
    if (!password || password.length < 8) {
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters." });
    }
    if (!githubToken || !githubToken.trim()) {
      return res.status(400).json({
        error: "A GitHub token is required to create an account - it powers every scan you run. Create one at https://github.com/settings/tokens (no scopes needed for public repos; add \"repo\" if you want to see private ones here too).",
      });
    }
    if (!TOKEN_RE.test(githubToken.trim())) {
      return res.status(400).json({ error: "That doesn't look like a valid GitHub token." });
    }
    let resolvedGithubUsername = null;
    if (githubUsername && githubUsername.trim()) {
      resolvedGithubUsername = extractGithubUsername(githubUsername);
      if (!resolvedGithubUsername) {
        return res.status(400).json({
          error: "That doesn't look like a valid GitHub username or profile URL.",
        });
      }
    }

    // A string that merely looks like a token (matches TOKEN_RE) isn't
    // necessarily a *working* one - confirm it against GitHub itself before
    // it's permanently tied to the new account. `valid === null` (GitHub
    // unreachable) doesn't block signup - a network hiccup here shouldn't
    // stop someone from creating an account with a token that's actually
    // fine; GitHub's next real API call is still the ultimate check either
    // way, same as everywhere else this module verifies a token.
    let tokenInfo = await verifyGithubToken(githubToken);
    if (tokenInfo.valid === false) {
      return res.status(400).json({ error: tokenInfo.reason });
    }
    // GitHub's own answer for who the token belongs to is more trustworthy
    // than a separately-typed username field - prefer it when the person
    // didn't already type one themselves.
    if (tokenInfo.valid === true && !resolvedGithubUsername && tokenInfo.login) {
      resolvedGithubUsername = tokenInfo.login;
    }

    if (await db.findUserByEmail(email)) {
      return res.status(409).json({ error: "An account with that email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await db.createUser({
      email,
      passwordHash,
      username: username || null,
      githubToken: githubToken && githubToken.trim() ? githubToken.trim() : null,
      githubUsername: resolvedGithubUsername,
    });

    res.status(201).json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) {
    console.error("❌ Register error:", error.message);
    res.status(500).json({ error: "Failed to create account." });
  }
});

// --- POST /api/auth/login ----------------------------------------------
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    let user = await db.findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    // Accounts created with "Continue with Google" have no password at all.
    if (!user.passwordHash) {
      return res.status(401).json({ error: "This account uses Google sign-in. Click \"Continue with Google\" instead." });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    user = await ensureSigningKey(user);
    res.json({ token: issueToken(user), user: publicUser(user) });
  } catch (error) {
    console.error("❌ Login error:", error.message);
    res.status(500).json({ error: "Failed to log in." });
  }
});

// --- GET /api/auth/google-config ---------------------------------------------
// The Google client id is public by design (it's embedded in every page that
// shows a Google button), so the frontend can fetch it instead of having it
// hard-coded. `null` means "not configured" and the page hides the button.
router.get("/google-config", (req, res) => {
  res.json({ clientId: getGoogleClientId() || null });
});

// --- POST /api/auth/google ---------------------------------------------------
// One endpoint for both "Sign in with Google" and "Sign up with Google": the
// account is created on first use. Body: { credential } - the ID token from
// Google Identity Services.
router.post("/google", async (req, res) => {
  try {
    const profile = await verifyGoogleCredential((req.body || {}).credential);
    let { user, isNew } = await signInWithGoogleProfile(profile);
    user = await ensureSigningKey(user);
    res.status(isNew ? 201 : 200).json({ token: issueToken(user), user: publicUser(user), isNew });
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error("❌ Google sign-in error:", error.message);
    res.status(500).json({ error: "Failed to sign in with Google." });
  }
});

// --- GET /api/auth/me ----------------------------------------------------
router.get("/me", requireAuth, async (req, res) => {
  const user = await db.findUserById(req.user.id);
  if (!user) return res.status(404).json({ error: "User not found." });
  res.json({ user: publicUser(user) });
});

// --- PUT /api/auth/github --------------------------------------------------
// Lets a signed-in user add/change/clear their personal GitHub token or
// username later without going back through signup.
router.put("/github", requireAuth, async (req, res) => {
  const { githubToken, githubUsername } = req.body || {};

  if (githubToken && githubToken.trim() && !TOKEN_RE.test(githubToken.trim())) {
    return res.status(400).json({ error: "That doesn't look like a valid GitHub token." });
  }
  let resolvedGithubUsername;
  if (githubUsername !== undefined) {
    if (githubUsername && githubUsername.trim()) {
      resolvedGithubUsername = extractGithubUsername(githubUsername);
      if (!resolvedGithubUsername) {
        return res.status(400).json({ error: "That doesn't look like a valid GitHub username or profile URL." });
      }
    } else {
      resolvedGithubUsername = null;
    }
  }

  // Same real-GitHub verification as signup - rotating in a new token from
  // Settings shouldn't silently accept something expired/revoked either.
  let tokenInfo = null;
  if (githubToken && githubToken.trim()) {
    tokenInfo = await verifyGithubToken(githubToken);
    if (tokenInfo.valid === false) {
      return res.status(400).json({ error: tokenInfo.reason });
    }
    if (tokenInfo.valid === true && resolvedGithubUsername === undefined && tokenInfo.login) {
      resolvedGithubUsername = tokenInfo.login;
    }
  }

  const user = await db.updateUserGithub(req.user.id, {
    githubToken: githubToken !== undefined ? (githubToken && githubToken.trim() ? githubToken.trim() : null) : undefined,
    githubUsername: resolvedGithubUsername,
  });

  res.json({
    user: publicUser(user),
    githubTokenVerification: tokenInfo
      ? {
          verified: tokenInfo.valid === true,
          login: tokenInfo.login || null,
          scopes: tokenInfo.scopes || [],
          note: tokenInfo.valid === null ? tokenInfo.reason : null,
        }
      : null,
  });
});

module.exports = router;
module.exports.issueToken = issueToken;
module.exports.publicUser = publicUser;
