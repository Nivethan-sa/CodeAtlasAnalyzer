// Every user has their own random secret (user.jwtSecret, generated at
// signup - see db/queries.js's createUser). Their actual token-signing key
// is this secret combined with the server-wide JWT_SECRET pepper - so
// leaking the database alone isn't enough to forge tokens (still need the
// server's env var too), and rotating ONE user's secret only invalidates
// THEIR sessions, not everyone's.
const crypto = require("crypto");

function computeSigningKey(user) {
  if (!user || !user.jwtSecret) return null;
  return crypto
    .createHmac("sha256", process.env.JWT_SECRET || "")
    .update(user.jwtSecret)
    .digest("hex");
}

module.exports = { computeSigningKey };
