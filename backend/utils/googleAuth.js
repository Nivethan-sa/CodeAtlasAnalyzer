// "Continue with Google" - server side.
//
// The browser (Google Identity Services) hands the page a signed ID token
// (a JWT issued by Google). The page sends that to POST /api/auth/google and
// we NEVER trust it as-is: verifyGoogleCredential() checks Google's signature,
// the expiry, and that the token was minted for OUR client id (the `aud`
// claim) - a token issued to some other website's Google button is rejected.
//
// Setup (once): Google Cloud Console -> APIs & Services -> Credentials ->
// Create OAuth client ID -> "Web application", add your site's origin under
// "Authorized JavaScript origins" (http://localhost:5001 for local use), and
// put the client id in backend/.env as GOOGLE_CLIENT_ID. No client secret is
// needed for this flow.
const { OAuth2Client } = require("google-auth-library");
const db = require("../db/queries");

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function getGoogleClientId() {
  return (process.env.GOOGLE_CLIENT_ID || "").trim();
}

let cachedClient = null;
let cachedClientId = null;
function defaultClient(clientId) {
  if (!cachedClient || cachedClientId !== clientId) {
    cachedClient = new OAuth2Client(clientId);
    cachedClientId = clientId;
  }
  return cachedClient;
}

/**
 * Verifies a Google ID token and returns the trusted profile.
 * `client` is injectable so tests don't need the network.
 * @throws {Error & {status:number}}
 */
async function verifyGoogleCredential(credential, { client } = {}) {
  const clientId = getGoogleClientId();
  if (!clientId) {
    throw httpError(503, "Google sign-in isn't set up on this server yet. Add GOOGLE_CLIENT_ID to backend/.env and restart.");
  }
  if (typeof credential !== "string" || credential.length < 20 || credential.length > 8192) {
    throw httpError(400, "Missing Google sign-in token.");
  }

  let payload;
  try {
    const ticket = await (client || defaultClient(clientId)).verifyIdToken({
      idToken: credential,
      audience: clientId,
    });
    payload = ticket.getPayload();
  } catch (error) {
    // Bad signature / expired / wrong audience all land here. Don't leak which.
    throw httpError(401, "Google couldn't verify that sign-in. Please try again.");
  }

  if (!payload || !payload.sub || !payload.email) {
    throw httpError(401, "Google didn't return an email address for that account.");
  }
  // An unverified email could belong to someone else - never trust it.
  if (payload.email_verified !== true) {
    throw httpError(401, "That Google account's email address isn't verified.");
  }
  return {
    googleId: String(payload.sub),
    email: String(payload.email),
    name: payload.name ? String(payload.name).slice(0, 80) : null,
    picture: typeof payload.picture === "string" && /^https:\/\//.test(payload.picture) ? payload.picture : null,
  };
}

/**
 * Turns a verified Google profile into a CodeAtlas account: returns the
 * existing one or creates a new one.
 *
 *  1. Known Google id            -> sign in.
 *  2. New Google id, new email   -> sign up (no password, no GitHub token yet).
 *  3. New Google id, email already has a PASSWORD account -> refuse. CodeAtlas
 *     doesn't verify emails on password signup, so silently merging would let
 *     someone who pre-registered another person's address keep a backdoor
 *     (their password) into the account that person later signs into with
 *     Google. The owner can still sign in with their password.
 *
 * @returns {{user: object, isNew: boolean}}
 */
async function signInWithGoogleProfile(profile) {
  const byGoogle = await db.findUserByGoogleId(profile.googleId);
  if (byGoogle) return { user: byGoogle, isNew: false };

  const existing =
    (await db.findUserByEmail(profile.email)) ||
    (profile.email !== profile.email.toLowerCase() ? await db.findUserByEmail(profile.email.toLowerCase()) : null);
  if (existing) {
    throw httpError(
      409,
      "An account with that email already exists and uses a password. Sign in with your email and password instead.",
    );
  }

  const user = await db.createUser({
    email: profile.email,
    passwordHash: null,
    username: profile.name,
    googleId: profile.googleId,
    avatarUrl: profile.picture,
  });
  return { user, isNew: true };
}

module.exports = { verifyGoogleCredential, signInWithGoogleProfile, getGoogleClientId };
