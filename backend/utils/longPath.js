const path = require("path");
const fs = require("fs");

/**
 * Windows has a historical 260-character MAX_PATH limit that Node's `fs`
 * module (and `git`) can hit well before you'd expect - a clone destination
 * nested a few folders deep (e.g. under `Downloads\New folder (2)\...`)
 * combined with a repo that has long, deeply-nested paths (Java/Maven
 * projects are the classic offender: `src/main/java/io/foo/bar/baz/...`) is
 * enough to blow past it. When that happens you get `git`'s own
 * "Filename too long" during checkout, and then a *second* failure when
 * cleanup tries to remove the same too-long paths - `fs.rmSync` throws
 * `EPERM`/`ENAMETOOLONG` instead of quietly retrying.
 *
 * Windows (NTFS) actually supports paths up to ~32,767 characters - the
 * 260 limit is an artifact of the older Win32 API - and both `fs` and NTFS
 * will honor that if the path is prefixed with `\\?\` (or `\\?\UNC\` for
 * network paths). This module centralizes that prefixing so every call
 * site doesn't have to reimplement it, and only actually does anything on
 * `win32` - it's a no-op on macOS/Linux, where none of this applies.
 */

function toLongPath(inputPath) {
  if (process.platform !== "win32" || !inputPath) return inputPath;

  const resolved = path.resolve(inputPath);
  if (resolved.startsWith("\\\\?\\")) return resolved; // already prefixed

  if (resolved.startsWith("\\\\")) {
    // UNC path, e.g. \\server\share\... -> \\?\UNC\server\share\...
    return `\\\\?\\UNC\\${resolved.slice(2)}`;
  }
  return `\\\\?\\${resolved}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Recursively removes `targetPath`, retrying transient Windows failures
 * (EBUSY/EPERM from an antivirus scan or an OS file-index handle that
 * hasn't let go of a just-cloned file yet) and using the long-path prefix
 * so deeply-nested repos don't fail cleanup even when the checkout itself
 * had to be aborted partway through.
 *
 * Async and non-blocking (retries wait via a real `setTimeout`, not a busy
 * loop, so it doesn't stall the rest of the server while it waits). Never
 * throws - logs and resolves to `false` on failure so a cleanup problem
 * never crashes or masks whatever request it's running alongside. Resolves
 * to `true` on success (or if there was nothing to remove).
 */
async function safeRemove(targetPath, { attempts = 5, retryDelayMs = 250, label } = {}) {
  if (!targetPath) return true;

  const longPath = toLongPath(targetPath);

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      if (!fs.existsSync(longPath)) return true;
      await fs.promises.rm(longPath, {
        recursive: true,
        force: true,
        // fs's own built-in retry, layered under ours - it only covers a
        // handful of transient error codes (EBUSY/EMFILE/ENFILE/ENOTEMPTY/
        // EPERM), which won't help with a plain "path too long" failure,
        // hence the outer retry loop + long-path prefix doing the real work.
        maxRetries: 3,
        retryDelay: 100,
      });
      return true;
    } catch (error) {
      if (attempt === attempts) {
        console.warn(
          `⚠️ Could not fully clean up${label ? ` ${label}` : ""} at "${targetPath}" after ${attempts} attempts (${error.code || error.message}). ` +
            "Leaving it behind rather than crashing the request - it can be deleted by hand, or will be overwritten next time this same path is used.",
        );
        return false;
      }
      await sleep(retryDelayMs * attempt); // small linear backoff
    }
  }
  return false;
}

module.exports = { toLongPath, safeRemove };
