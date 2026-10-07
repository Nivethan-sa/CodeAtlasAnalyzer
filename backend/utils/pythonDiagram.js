const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const RUNNER = path.join(__dirname, "..", "diagrams", "run_diagram.py");
const RUN_TIMEOUT_MS = 12000;
const MAX_STDOUT_BYTES = 600 * 1024;

let cachedPython; // undefined = not looked up yet, null = none found

/** Finds a Python 3 interpreter: PYTHON_BIN first, then python3 / python / py -3. */
function findPython() {
  if (cachedPython !== undefined) return cachedPython;
  const candidates = [];
  if (process.env.PYTHON_BIN) candidates.push([process.env.PYTHON_BIN]);
  candidates.push(["python3"], ["python"], ["py", "-3"]);
  for (const [cmd, ...pre] of candidates) {
    try {
      const r = spawnSync(cmd, [...pre, "-c", "import sys;print(sys.version_info[0])"], {
        encoding: "utf8",
        timeout: 5000,
      });
      if (r.status === 0 && r.stdout.trim() === "3") {
        cachedPython = { cmd, pre };
        return cachedPython;
      }
    } catch {
      /* try next */
    }
  }
  cachedPython = null;
  return null;
}

/**
 * Runs an AI-written diagram script in an isolated Python process and returns
 * { ok: true, dot } or { ok: false, error }. Never throws.
 * See diagrams/run_diagram.py for the safety layers; the process-level ones
 * (empty temp cwd, scrubbed env, wall-clock kill, output cap) live here.
 */
function runDiagramCode(code) {
  return new Promise((resolve) => {
    const py = findPython();
    if (!py) {
      return resolve({
        ok: false,
        error: "Python 3 was not found on the server. Install Python 3 (or set PYTHON_BIN in backend/.env) to use AI-generated diagrams.",
      });
    }

    let cwd;
    try {
      cwd = fs.mkdtempSync(path.join(os.tmpdir(), "codeatlas-diagram-"));
    } catch (e) {
      return resolve({ ok: false, error: `Could not create a temp folder: ${e.message}` });
    }
    const cleanup = () => fs.rm(cwd, { recursive: true, force: true }, () => {});

    // Scrubbed environment: no API keys, tokens or DB strings reach the script.
    const env = { PATH: process.env.PATH || "", PYTHONIOENCODING: "utf-8" };
    if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot; // Windows needs it to start

    const child = spawn(py.cmd, [...py.pre, "-I", RUNNER], { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    let finished = false;
    const done = (result) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      cleanup();
      resolve(result);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      done({ ok: false, error: "The diagram script took too long and was stopped." });
    }, RUN_TIMEOUT_MS);

    child.stdout.on("data", (d) => {
      out += d;
      if (out.length > MAX_STDOUT_BYTES) {
        child.kill("SIGKILL");
        done({ ok: false, error: "The diagram script produced too much output." });
      }
    });
    child.stderr.on("data", (d) => {
      if (err.length < 2000) err += d;
    });
    child.on("error", (e) => done({ ok: false, error: `Could not start Python: ${e.message}` }));
    child.on("close", () => {
      try {
        const parsed = JSON.parse(out);
        if (parsed && parsed.ok && typeof parsed.dot === "string") return done({ ok: true, dot: parsed.dot });
        return done({ ok: false, error: (parsed && parsed.error) || "The diagram script failed." });
      } catch {
        const hint = err.trim().split("\n").slice(-1)[0];
        return done({ ok: false, error: `The diagram script failed to run${hint ? `: ${hint}` : "."}` });
      }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(code);
  });
}

module.exports = { runDiagramCode, findPython };
