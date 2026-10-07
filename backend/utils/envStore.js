const fs = require("fs");
const path = require("path");

const ENV_PATH = path.join(__dirname, "..", ".env");

/**
 * Upserts KEY=VALUE pairs into backend/.env, preserving every other line
 * (comments, blank lines, unrelated vars) untouched, and mirrors each
 * change onto process.env immediately so the running server picks it up
 * without a restart. Creates the file if it doesn't exist yet - this is
 * what lets the in-browser Setup screen configure JWT_SECRET/GITHUB_TOKEN
 * on a totally fresh checkout that has no backend/.env at all.
 */
function upsertEnvValues(values) {
  let raw = "";
  try {
    raw = fs.readFileSync(ENV_PATH, "utf8");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const lines = raw.length ? raw.split(/\r?\n/) : [];
  const remainingKeys = new Set(Object.keys(values));

  const updatedLines = lines.map((line) => {
    const match = line.match(/^([A-Z0-9_]+)=/i);
    if (match && remainingKeys.has(match[1])) {
      const key = match[1];
      remainingKeys.delete(key);
      return `${key}=${values[key]}`;
    }
    return line;
  });

  for (const key of remainingKeys) {
    updatedLines.push(`${key}=${values[key]}`);
  }

  fs.writeFileSync(ENV_PATH, updatedLines.join("\n").replace(/\n{3,}/g, "\n\n"));

  for (const [key, value] of Object.entries(values)) {
    process.env[key] = value;
  }
}

module.exports = { upsertEnvValues, ENV_PATH };
