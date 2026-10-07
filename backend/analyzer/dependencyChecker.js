const fs = require("fs");
const path = require("path");
const axios = require("axios");

// Our DevSecOps Dictionary of notoriously vulnerable package versions.
// Kept as a fast, offline, always-available first line of defense -
// doesn't need network access and still catches the handful of
// best-known cases even if OSV.dev (below) is unreachable.
const VULNERABILITY_DB = {
  lodash: {
    vulnerable_below: "4.17.21",
    severity: "HIGH",
    threat: "Prototype Pollution",
  },
  axios: {
    vulnerable_below: "0.21.1",
    severity: "HIGH",
    threat: "Server-Side Request Forgery (SSRF)",
  },
  express: {
    vulnerable_below: "4.16.0",
    severity: "MEDIUM",
    threat: "Denial of Service (DoS)",
  },
  django: {
    vulnerable_below: "3.2.0",
    severity: "CRITICAL",
    threat: "SQL Injection vulnerability",
  },
  requests: {
    vulnerable_below: "2.31.0",
    severity: "MEDIUM",
    threat: "Data Leakage",
  },
  jsonwebtoken: {
    vulnerable_below: "9.0.0",
    severity: "CRITICAL",
    threat: "Remote Code Execution (RCE)",
  },
};

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const OSV_BATCH_SIZE = 100; // OSV's batch endpoint accepts far more than this, but keep requests small and fast
const OSV_MAX_DETAIL_LOOKUPS = 25; // cap follow-up detail calls to actual hits, not every dependency
const OSV_TIMEOUT_MS = 8000;

/**
 * Converts a version string like "^4.17.20" into a single comparable
 * number (major*1e6 + minor*1e3 + patch), so 4.17.20 and 4.17.21 compare
 * correctly. (An earlier version of this used parseFloat on a
 * dot-padded string, e.g. parseFloat("004.017.020") - which silently
 * collapses at the *second* dot since a number can only have one decimal
 * point, so 4.17.20 and 4.17.21 both became 4.017 and never compared as
 * different. This carries each part with its own fixed weight instead.)
 */
function parseVersion(versionString) {
  const clean = versionString.replace(/[\^~=<>]/g, "").trim();
  const parts = clean.split(".").map((p) => parseInt(p, 10) || 0);
  while (parts.length < 3) parts.push(0);
  return parts[0] * 1_000_000 + parts[1] * 1_000 + parts[2];
}

// OSV needs one *concrete* version per query, not a range - `^4.17.0`,
// `>=1.2.0`, `*`, and multi-constraint strings like `>=1.0 <2.0` can't be
// resolved to a single version without a real semver-range resolver, so
// those are skipped for the OSV check (they still get the plain hardcoded
// check above, which only needs a lower bound). Returns null to mean
// "skip this one for OSV" rather than guessing.
function cleanVersionForOsv(versionString) {
  if (!versionString) return null;
  const trimmed = versionString.trim();
  if (!trimmed || trimmed === "*" || trimmed.includes("||") || trimmed.includes(" ")) return null;
  const clean = trimmed.replace(/^[\^~=]+/, "").trim();
  // Must look like a real, fully-specified version - reject anything with
  // range operators or leftover wildcards after stripping the common ones.
  if (/[<>*]/.test(clean)) return null;
  if (!/^\d+(\.\d+){0,3}(-[0-9A-Za-z.-]+)?$/.test(clean)) return null;
  return clean;
}

/** Parses package.json's dependencies + devDependencies into a flat list. */
function collectNodeDependencies(repoPath) {
  const pkgPath = path.join(repoPath, "package.json");
  if (!fs.existsSync(pkgPath)) return [];
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    return Object.entries(allDeps).map(([name, version]) => ({ name, version: String(version) }));
  } catch (e) {
    console.error("Failed to parse package.json for dependencies.");
    return [];
  }
}

/** Parses requirements.txt's `name==version` / `name>=version` lines into a flat list. */
function collectPythonDependencies(repoPath) {
  const reqPath = path.join(repoPath, "requirements.txt");
  if (!fs.existsSync(reqPath)) return [];
  try {
    const content = fs.readFileSync(reqPath, "utf-8");
    const deps = [];
    content.split("\n").forEach((line) => {
      if (!line.includes("==") && !line.includes(">=")) return;
      const [pkgName, version] = line.split(/[=<>]+/);
      if (!pkgName || !version) return;
      deps.push({ name: pkgName.trim().toLowerCase(), version: version.trim() });
    });
    return deps;
  } catch (e) {
    console.error("Failed to parse requirements.txt.");
    return [];
  }
}

/** The original, offline, no-network vulnerability check against a small
 *  hardcoded dictionary of well-known bad versions. */
function checkHardcodedDb(nodeDeps, pyDeps) {
  const alerts = [];

  for (const { name, version } of nodeDeps) {
    const known = VULNERABILITY_DB[name];
    if (!known) continue;
    if (parseVersion(version) < parseVersion(known.vulnerable_below)) {
      alerts.push({
        type: "Vulnerable Dependency",
        file: "package.json",
        line: "N/A",
        severity: known.severity,
        snippet: `Found ${name}@${version}. Upgrade to v${known.vulnerable_below} to patch ${known.threat}.`,
      });
    }
  }

  for (const { name, version } of pyDeps) {
    const known = VULNERABILITY_DB[name];
    if (!known) continue;
    if (parseVersion(version) < parseVersion(known.vulnerable_below)) {
      alerts.push({
        type: "Vulnerable Dependency",
        file: "requirements.txt",
        line: "N/A",
        severity: known.severity,
        snippet: `Found ${name}@${version}. Upgrade to v${known.vulnerable_below} to patch ${known.threat}.`,
      });
    }
  }

  return alerts;
}

// Best-effort mapping from OSV's severity data (CVSS vector strings, or
// occasionally a bare "database_specific" severity string) down to the
// same HIGH/MEDIUM/LOW/CRITICAL vocabulary the hardcoded check already
// uses, so the frontend doesn't need two different severity scales.
function severityFromOsvVuln(vuln) {
  const dbSeverity = vuln?.database_specific?.severity;
  if (typeof dbSeverity === "string") return dbSeverity.toUpperCase();

  const cvssEntry = (vuln?.severity || []).find((s) => typeof s.score === "string");
  const score = cvssEntry && parseFloat((cvssEntry.score.match(/\/(\d+(\.\d+)?)$/) || [])[1]);
  if (Number.isFinite(score)) {
    if (score >= 9) return "CRITICAL";
    if (score >= 7) return "HIGH";
    if (score >= 4) return "MEDIUM";
    return "LOW";
  }
  return "UNKNOWN";
}

/**
 * Checks a set of dependencies against OSV.dev's batch query API
 * (https://osv.dev - no API key required) for known CVEs/advisories.
 *
 * Deliberately batches everything (OSV's own batch endpoint is built for
 * exactly this - dozens/hundreds of packages per request instead of one
 * request per dependency), has a hard timeout, and swallows every failure
 * mode (network error, timeout, malformed response, OSV outage) into an
 * empty result plus a console warning - a scan that would otherwise
 * succeed must never fail because a third-party security API is down.
 *
 * @param {Array<{name: string, version: string}>} nodeDeps
 * @param {Array<{name: string, version: string}>} pyDeps
 * @returns {Promise<Array>} alert objects, same shape as checkHardcodedDb's
 */
async function checkOsv(nodeDeps, pyDeps, { timeoutMs = OSV_TIMEOUT_MS } = {}) {
  // Build one query per dependency that has a concrete, resolvable version -
  // ranges/wildcards are skipped here (see cleanVersionForOsv) since OSV
  // needs an exact version to check.
  const candidates = [
    ...nodeDeps.map((d) => ({ ...d, ecosystem: "npm", file: "package.json" })),
    ...pyDeps.map((d) => ({ ...d, ecosystem: "PyPI", file: "requirements.txt" })),
  ]
    .map((d) => ({ ...d, cleanVersion: cleanVersionForOsv(d.version) }))
    .filter((d) => d.cleanVersion);

  if (candidates.length === 0) return [];

  const alerts = [];

  try {
    // Chunk into batches so a very large dependency tree still sends a
    // handful of requests instead of one giant one or hundreds of tiny ones.
    for (let i = 0; i < candidates.length; i += OSV_BATCH_SIZE) {
      const batch = candidates.slice(i, i + OSV_BATCH_SIZE);
      const response = await axios.post(
        OSV_BATCH_URL,
        {
          queries: batch.map((d) => ({
            package: { name: d.name, ecosystem: d.ecosystem },
            version: d.cleanVersion,
          })),
        },
        { timeout: timeoutMs },
      );

      const results = response.data?.results || [];
      let detailLookupsUsed = 0;

      for (let j = 0; j < results.length; j++) {
        const vulnIds = (results[j]?.vulns || []).map((v) => v.id).filter(Boolean);
        if (vulnIds.length === 0) continue;
        const dep = batch[j];

        // The batch endpoint intentionally returns minimal info (just IDs)
        // to keep it fast - fetch full details (summary/severity) only for
        // packages that actually hit something, and cap how many of those
        // we bother resolving so one dependency with 40 historical
        // advisories can't turn this into 40 more requests.
        const topId = vulnIds[0];
        let summary = null;
        let severity = "UNKNOWN";
        if (detailLookupsUsed < OSV_MAX_DETAIL_LOOKUPS) {
          detailLookupsUsed++;
          try {
            const detail = await axios.get(`${OSV_VULN_URL}/${encodeURIComponent(topId)}`, {
              timeout: timeoutMs,
            });
            summary = detail.data?.summary || detail.data?.details || null;
            severity = severityFromOsvVuln(detail.data);
          } catch {
            // Detail lookup failing doesn't mean the vuln isn't real - still
            // report it, just without a human-readable summary/severity.
          }
        }

        const extraCount = vulnIds.length - 1;
        alerts.push({
          type: "Known CVE (OSV.dev)",
          file: dep.file,
          line: "N/A",
          severity,
          snippet:
            `${dep.name}@${dep.cleanVersion} is affected by ${topId}` +
            (summary ? `: ${summary}` : "") +
            (extraCount > 0 ? ` (+${extraCount} more advisory${extraCount === 1 ? "" : "ies"} for this version)` : ""),
        });
      }
    }
  } catch (error) {
    console.warn("⚠️ OSV.dev dependency check unavailable, skipping known-CVE scan:", error.message);
    return [];
  }

  return alerts;
}

/**
 * Scans repository root for manifest files and checks for vulnerable
 * dependencies - both against the small offline dictionary above, and
 * (network permitting) against OSV.dev's real vulnerability database.
 * Never throws: any failure in the OSV portion just means fewer results,
 * not a failed scan.
 */
async function auditDependencies(repoPath) {
  const nodeDeps = collectNodeDependencies(repoPath);
  const pyDeps = collectPythonDependencies(repoPath);

  const hardcodedAlerts = checkHardcodedDb(nodeDeps, pyDeps);

  let osvAlerts = [];
  try {
    osvAlerts = await checkOsv(nodeDeps, pyDeps);
  } catch (error) {
    // checkOsv already catches internally and resolves to [] - this is
    // just an extra backstop in case that contract is ever broken.
    console.warn("⚠️ Unexpected error running the OSV.dev check:", error.message);
  }

  return [...hardcodedAlerts, ...osvAlerts];
}

module.exports = auditDependencies;
// Exposed for targeted unit testing without needing real network access.
module.exports.checkOsv = checkOsv;
module.exports.checkHardcodedDb = checkHardcodedDb;
module.exports.collectNodeDependencies = collectNodeDependencies;
module.exports.collectPythonDependencies = collectPythonDependencies;
module.exports.cleanVersionForOsv = cleanVersionForOsv;
