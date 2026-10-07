const jwt = require("jsonwebtoken");
const db = require("../db/queries");
const { computeSigningKey } = require("../utils/jwtKey");

function readToken(req) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme === "Bearer" && token) return token;
  return null;
}

/**
 * Verifies a token against the specific user it claims to be, not one
 * secret shared by every account. jwt.decode() reads the unverified
 * payload just far enough to get the claimed user id, then jwt.verify()
 * checks the signature against THAT user's derived key (see
 * utils/jwtKey.js). A token can never verify as a different user than the
 * one it was actually signed for, and rotating one user's secret can never
 * invalidate anyone else's session.
 */
async function verifyAndLoadUser(token) {
  const unverified = jwt.decode(token);
  if (!unverified || !unverified.sub) return null;

  const user = await db.findUserById(unverified.sub);
  if (!user) return null;

  const signingKey = computeSigningKey(user);
  if (!signingKey) return null;

  jwt.verify(token, signingKey); // throws if invalid/expired/mismatched
  return user;
}

/**
 * Attaches req.user if a valid token is present, but never blocks the
 * request otherwise. CodeAtlas lets anyone run a scan; being logged in
 * just means the scan gets attributed to your account so it shows up
 * in "My Scans" instead of the anonymous public feed.
 */
async function optionalAuth(req, res, next) {
  const token = readToken(req);
  if (!token) return next();

  try {
    const user = await verifyAndLoadUser(token);
    if (user) req.user = { id: user.id, email: user.email };
  } catch (error) {
    // Invalid/expired token - treat the request as anonymous instead
    // of erroring, since auth here is additive, not load-bearing.
  }
  next();
}

/**
 * Hard-blocks the request unless a valid token is present. Used for
 * account-scoped actions like deleting a scan.
 */
async function requireAuth(req, res, next) {
  const token = readToken(req);
  if (!token) {
    return res.status(401).json({ error: "Authentication required." });
  }

  try {
    const user = await verifyAndLoadUser(token);
    if (!user) {
      return res.status(401).json({ error: "Invalid or expired session." });
    }
    req.user = { id: user.id, email: user.email };
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired session." });
  }
}

module.exports = { optionalAuth, requireAuth };
