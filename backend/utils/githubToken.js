const axios = require("axios");

const USER_AGENT = "CodeAtlas-Analyzer";

/**
 * Verifies a GitHub token by actually calling GitHub with it, instead of
 * only checking that it *looks* like a token (routes/auth.js's TOKEN_RE
 * just checks shape/length). A string can match ghp_/github_pat_ shape and
 * still be expired, revoked, or plain made up - the only way to know is to
 * ask GitHub.
 *
 * Uses GET /user - the cheapest authenticated endpoint GitHub offers, and
 * one every token (classic or fine-grained) can call regardless of scope.
 * It also hands back two things worth having:
 *   - `login`: the account the token actually belongs to, so callers can
 *     auto-fill githubUsername instead of trusting a separately-typed
 *     field that could point at a different account entirely.
 *   - `scopes`: parsed from the `x-oauth-scopes` response header (classic
 *     tokens only - fine-grained tokens don't send this header, which is
 *     why `scopes` may come back empty even for a perfectly valid token).
 *
 * Deliberately distinguishes "the token is bad" (valid: false - GitHub
 * answered and said no) from "couldn't check" (valid: null - network
 * error, GitHub outage, timeout). Callers should block saving on the
 * former but not the latter: a flaky connection on our end shouldn't stop
 * someone from saving a token that's actually fine.
 */
async function verifyGithubToken(token, { timeoutMs = 8000 } = {}) {
  if (!token || !token.trim()) {
    return { valid: false, reason: "No token provided." };
  }

  try {
    const response = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `token ${token.trim()}`, "User-Agent": USER_AGENT },
      timeout: timeoutMs,
    });

    const scopesHeader = response.headers?.["x-oauth-scopes"] || "";
    const scopes = scopesHeader
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    return { valid: true, login: response.data.login, scopes };
  } catch (error) {
    if (error.response && (error.response.status === 401 || error.response.status === 403)) {
      return {
        valid: false,
        reason:
          error.response.status === 401
            ? "GitHub rejected this token - it may be invalid, expired, or revoked."
            : "GitHub refused this token (403) - it may lack required permissions or be an unverified/suspended account.",
      };
    }
    return {
      valid: null,
      reason: "Could not reach GitHub to verify the token right now.",
    };
  }
}

/**
 * Reads GitHub's own /rate_limit endpoint - works with or without a token
 * (anonymous requests just get the 60/hour bucket instead of 5,000/hour).
 * Used to surface "you have N requests left" in the UI instead of only
 * finding out via a 429 mid-scan.
 */
async function getRateLimit(token, { timeoutMs = 8000 } = {}) {
  try {
    const headers = { "User-Agent": USER_AGENT };
    if (token) headers.Authorization = `token ${token}`;

    const response = await axios.get("https://api.github.com/rate_limit", {
      headers,
      timeout: timeoutMs,
    });

    const core = response.data?.resources?.core;
    if (!core) return null;

    return {
      limit: core.limit,
      remaining: core.remaining,
      resetsAt: new Date(core.reset * 1000).toISOString(),
      authenticated: Boolean(token),
    };
  } catch (error) {
    // Rate-limit status is a nice-to-have, never worth failing a request
    // over - callers get null and just skip showing it.
    return null;
  }
}

module.exports = { verifyGithubToken, getRateLimit };
