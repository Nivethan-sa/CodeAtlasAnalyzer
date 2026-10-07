const Sentry = require("@sentry/node");

Sentry.init({
  dsn: "https://ed2b57e0b7c090727e331dd21e7f25cb@o4512179836878848.ingest.de.sentry.io/4512179875676240",
  debug: true,
});

Sentry.captureException(new Error("Standalone Sentry test"));

Sentry.flush(5000).then((ok) => console.log("flushed:", ok));
