/**
 * Parses a GitHub URL or "owner/repo" shorthand into safe components.
 * Returns null if the input doesn't look like a real GitHub reference -
 * this is the first line of defense before we ever touch the filesystem
 * or a child process with user-supplied text.
 */
function parseGithubRepoInput(input) {
  if (!input || typeof input !== "string") return null;

  let trimmed = input.trim();

  // Strip protocol + host if a full URL was pasted, plus any query string
  // or hash fragment (e.g. "?tab=readme-ov-file", "#readme") that a
  // copy-pasted browser URL might carry.
  trimmed = trimmed
    .replace(/^https?:\/\/(www\.)?github\.com\//i, "")
    .replace(/[?#].*$/, "")
    .replace(/\.git$/i, "")
    .replace(/\/+$/, "");

  const parts = trimmed.split("/").filter(Boolean);
  if (parts.length < 2) return null;

  // Reject traversal segments anywhere in the path, not just in the
  // owner/repo pair - belt and suspenders even though only the first two
  // segments end up being used downstream.
  if (parts.some((p) => p === "." || p === "..")) return null;

  // Take the FIRST two segments as owner/repo. GitHub URLs routinely carry
  // extra path segments after owner/repo - a branch view
  // ("/tree/main"), a file view ("/blob/main/src/index.js"), a PR
  // ("/pull/12") - all of which are exactly what someone copies out of
  // their browser address bar. Using the last two segments (the previous
  // behavior) would parse ".../tree/main" as owner="tree", repo="main"
  // and send that straight to GitHub's API, which naturally 404s.
  const owner = parts[0];
  const repo = parts[1];

  // GitHub owner/repo names are limited to alphanumerics, hyphens,
  // underscores and dots. Anything else (spaces, semicolons, slashes,
  // "..", shell metacharacters) is rejected outright rather than
  // "cleaned up" - a rejected scan is safe, a silently-modified one
  // isn't.
  const SAFE_SEGMENT = /^[A-Za-z0-9._-]{1,100}$/;
  if (!SAFE_SEGMENT.test(owner) || !SAFE_SEGMENT.test(repo)) return null;
  if (owner === "." || owner === ".." || repo === "." || repo === "..") {
    return null;
  }

  return { owner, repo };
}

/**
 * Same allow-list check for a bare GitHub username (used by the
 * profile/batch-scan endpoint).
 */
function isSafeGithubUsername(input) {
  return typeof input === "string" && /^[A-Za-z0-9-]{1,39}$/.test(input.trim());
}

module.exports = { parseGithubRepoInput, isSafeGithubUsername };
