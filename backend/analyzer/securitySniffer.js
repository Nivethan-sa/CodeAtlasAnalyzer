const fs = require("fs");
const path = require("path");
const { toLongPath } = require("../utils/longPath");

// The "Bloodhound" Dictionary: Regex patterns for catastrophic leaks
const DANGEROUS_PATTERNS = [
  { type: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/, severity: "CRITICAL" },
  {
    type: "RSA/SSH Private Key",
    // Built from fragments rather than one literal PEM-header regex, so this
    // file's own source never contains five contiguous hyphens next to the
    // words "BEGIN"/"PRIVATE KEY" - otherwise this scanner flags itself as a
    // leaked key the moment it scans its own repository (which the CI
    // workflow does on every PR - a false "CRITICAL" finding here means
    // Grade F on every single run, regardless of what the PR changed).
    regex: new RegExp(["-{5}BEGIN", ".*", "PRIVATE KEY-{5}"].join(" ")),
    severity: "CRITICAL",
  },
  {
    type: "Hardcoded API Token/Password",
    regex:
      /(?:api_key|apikey|secret_key|auth_token|access_token|password)[\s:=]+['"]([a-zA-Z0-9\-_=]{12,})['"]/i,
    severity: "HIGH",
  },
];

/**
 * Scans a file line-by-line for leaked secrets and passwords.
 * @param {string} filePath - Absolute path to the file.
 * @returns {Array} - List of found vulnerabilities.
 */
function sniffSecrets(filePath) {
  let content = "";
  try {
    content = fs.readFileSync(toLongPath(filePath), "utf-8");
  } catch (error) {
    return [];
  }

  const vulnerabilities = [];
  const lines = content.split("\n");

  lines.forEach((line, index) => {
    // Skip minified/bundled files (lines that are insanely long) to prevent memory crashes
    if (line.length > 500) return;

    DANGEROUS_PATTERNS.forEach((pattern) => {
      if (pattern.regex.test(line)) {
        vulnerabilities.push({
          file: path.basename(filePath),
          line: index + 1, // +1 because arrays start at 0, but code lines start at 1
          type: pattern.type,
          severity: pattern.severity,
          // We truncate the snippet so the UI doesn't display the actual usable password
          snippet: line.trim().substring(0, 45) + "...",
        });
      }
    });
  });

  return vulnerabilities;
}

module.exports = sniffSecrets;
