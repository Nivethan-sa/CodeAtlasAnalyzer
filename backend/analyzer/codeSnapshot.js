const fs = require("fs");
const path = require("path");
const { toLongPath } = require("../utils/longPath");

/**
 * Reads the actual source code of a cloned repository into a bounded
 * "snapshot" that the chat agent can send to Gemini, so answers are based on
 * the real code and not only on the scan's summary.
 *
 * The clone is deleted right after the scan, so this has to run BEFORE
 * cleanup (see /api/analyze in server.js). The result is stored in the
 * `scanSources` collection, keyed by scan id.
 *
 * Safety / size rules:
 *  - never reads .env files, private keys, certificates or lockfiles
 *  - skips binaries, minified bundles and very large files
 *  - redacts strings that look like API keys/tokens before they leave the box
 *  - stops at a character budget (default 400k chars ~= 100k tokens), which
 *    fits comfortably in Gemini's context window. Override with
 *    CHAT_CODE_CHAR_BUDGET in backend/.env.
 */

const IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  "venv",
  ".venv",
  "__pycache__",
  "dist",
  "build",
  ".next",
  "coverage",
  "vendor",
  "target",
  ".idea",
  ".vscode",
]);

const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp", ".pdf",
  ".zip", ".gz", ".tar", ".7z", ".rar", ".jar", ".war", ".exe", ".dll",
  ".so", ".dylib", ".class", ".pyc", ".woff", ".woff2", ".ttf", ".eot",
  ".mp3", ".mp4", ".mov", ".avi", ".wav", ".bin", ".dat", ".db", ".sqlite",
  ".map", ".lock",
]);

const SKIP_NAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "composer.lock",
  "Gemfile.lock",
  "poetry.lock",
  "Cargo.lock",
]);

// Secrets: never even read these.
const SECRET_FILE_RE = /(^\.env($|\.))|\.(pem|key|p12|pfx|crt|cer|keystore)$|^id_(rsa|dsa|ecdsa|ed25519)/i;

// Files worth showing the model first when the budget is tight.
const PRIORITY_NAMES = new Set([
  "readme.md", "package.json", "requirements.txt", "pyproject.toml",
  "pom.xml", "build.gradle", "go.mod", "cargo.toml", "dockerfile",
  "docker-compose.yml", "server.js", "app.js", "index.js", "main.js",
  "main.py", "app.py", "manage.py", "main.go", "index.ts", "main.ts",
]);

const MAX_FILE_BYTES = 200 * 1024; // skip anything bigger than this
const MAX_CHARS_PER_FILE = 40000; // truncate very long files
const DEFAULT_BUDGET = 400000;

const REDACTIONS = [
  /ghp_[A-Za-z0-9]{20,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /AIza[0-9A-Za-z_\-]{30,}/g,
  /sk-[A-Za-z0-9_\-]{20,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /mongodb(\+srv)?:\/\/[^\s'"`]+/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

function redact(text) {
  let out = text;
  for (const re of REDACTIONS) out = out.replace(re, "[REDACTED]");
  return out;
}

function looksBinary(text) {
  return text.includes("\u0000");
}

function collectFiles(root) {
  const found = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(toLongPath(dir), { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) walk(path.join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      const name = entry.name;
      if (SKIP_NAMES.has(name) || SECRET_FILE_RE.test(name)) continue;
      if (BINARY_EXT.has(path.extname(name).toLowerCase())) continue;
      if (/\.min\.(js|css)$/i.test(name)) continue;

      const full = path.join(dir, name);
      let size;
      try {
        size = fs.statSync(toLongPath(full)).size;
      } catch {
        continue;
      }
      if (size === 0 || size > MAX_FILE_BYTES) continue;

      const rel = path.relative(root, full).split(path.sep).join("/");
      found.push({ full, rel, size, depth: rel.split("/").length - 1 });
    }
  };
  walk(root);
  return found;
}

function rank(file) {
  const base = path.basename(file.rel).toLowerCase();
  const priority = PRIORITY_NAMES.has(base) ? 0 : 1;
  const isTest = /(^|\/)(tests?|__tests__|spec)\//i.test(file.rel) || /\.(test|spec)\./i.test(base) ? 1 : 0;
  return [priority, isTest, file.depth, file.size];
}

function compare(a, b) {
  const ra = rank(a);
  const rb = rank(b);
  for (let i = 0; i < ra.length; i++) {
    if (ra[i] !== rb[i]) return ra[i] - rb[i];
  }
  return a.rel.localeCompare(b.rel);
}

/**
 * @param {string} repoPath - path of the cloned repository
 * @returns {{files: {path: string, content: string}[], totalFiles: number, includedFiles: number, truncated: boolean, totalChars: number}}
 */
function buildCodeSnapshot(repoPath) {
  const budget = parseInt(process.env.CHAT_CODE_CHAR_BUDGET, 10) || DEFAULT_BUDGET;
  const candidates = collectFiles(repoPath).sort(compare);

  const files = [];
  let used = 0;
  let truncated = false;

  for (const file of candidates) {
    if (used >= budget) {
      truncated = true;
      break;
    }
    let content;
    try {
      content = fs.readFileSync(toLongPath(file.full), "utf-8");
    } catch {
      continue;
    }
    if (!content.trim() || looksBinary(content)) continue;

    content = redact(content);
    if (content.length > MAX_CHARS_PER_FILE) {
      content = content.slice(0, MAX_CHARS_PER_FILE) + "\n/* ...file truncated... */";
      truncated = true;
    }
    if (used + content.length > budget) {
      truncated = true;
      continue; // a smaller file later in the list might still fit
    }
    files.push({ path: file.rel, content });
    used += content.length;
  }

  return {
    files,
    totalFiles: candidates.length,
    includedFiles: files.length,
    truncated,
    totalChars: used,
  };
}

/** Renders the snapshot as one block of text for the model prompt. */
function formatSnapshotForPrompt(snapshot) {
  if (!snapshot || !snapshot.files || snapshot.files.length === 0) return "";
  const header =
    `SOURCE CODE (${snapshot.includedFiles} of ${snapshot.totalFiles} files` +
    `${snapshot.truncated ? ", some files omitted or truncated for size" : ""}):\n`;
  const body = snapshot.files
    .map((f) => `\n=== FILE: ${f.path} ===\n${f.content}`)
    .join("\n");
  return header + body + "\n";
}

module.exports = { buildCodeSnapshot, formatSnapshotForPrompt };
