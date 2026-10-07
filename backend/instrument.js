// Must be the FIRST thing server.js requires so Sentry can instrument
// express/http before they load. dotenv is loaded here too because this file
// runs before server.js calls dotenv.config() - without it NODE_ENV and
// SENTRY_DSN from backend/.env would be undefined at init time.
require("dotenv").config({ path: require("path").join(__dirname, ".env") });
const Sentry = require("@sentry/node");

Sentry.init({
  // Put SENTRY_DSN in backend/.env to override; the fallback keeps the
  // current project working.
  dsn:
    process.env.SENTRY_DSN ||
    "https://ed2b57e0b7c090727e331dd21e7f25cb@o4512179836878848.ingest.de.sentry.io/4512179875676240",
  environment: process.env.NODE_ENV || "development",
  sendDefaultPii: false, // don't attach IPs/cookies/auth headers to events
  tracesSampleRate: process.env.NODE_ENV === "production" ? 0.2 : 1.0,
});
