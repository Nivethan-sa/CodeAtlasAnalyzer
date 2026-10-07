const fs = require("fs");
const path = require("path");
const { toLongPath } = require("../utils/longPath");

/**
 * Best-effort, single-file call-graph extraction: which locally-defined
 * function calls which other locally-defined function, plus three tags
 * used to anchor a real "how data flows through this system" diagram
 * (see frontend's buildSystemFlowDiagram):
 *   - is_route_handler / route: this function is directly wired to an API
 *     endpoint (Flask/Express-style decorator or route registration).
 *   - touches_db: this function's body calls a recognizable
 *     database-driver method (pymongo, the native Mongo driver, a
 *     Mongoose/Sequelize/TypeORM-style call, or raw SQL execute).
 *   - produces_output: this function's body returns/sends a response
 *     (jsonify/render_template/res.json/res.send/...).
 *
 * Like every other extractor in this file, this is regex/text-based, not
 * a real parser or interpreter, and is entirely single-file - a function
 * that calls something imported from another file is invisible here. That
 * keeps it fast and dependency-free, at the cost of missing cross-file
 * call chains; the frontend's diagram builder already knows to fall back
 * to coarser heuristics when this doesn't turn up a connected pipeline.
 *
 * @param {string} filePath - Absolute path to the file.
 * @returns {Array<{name, calls: string[], is_route_handler: boolean, route: {method,endpoint}|null, touches_db: boolean, produces_output: boolean}>}
 */
function extractCallGraph(filePath) {
  const ext = path.extname(filePath);
  let content = "";
  try {
    content = fs.readFileSync(toLongPath(filePath), "utf-8");
  } catch (error) {
    return [];
  }

  const JS_EXTS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
  let rawFunctions = [];
  if (ext === ".py") rawFunctions = extractPythonFunctions(content);
  else if (JS_EXTS.has(ext)) rawFunctions = extractJsFunctions(content);
  else return [];

  if (rawFunctions.length === 0) return [];

  const knownNames = new Set(rawFunctions.map((f) => f.name));

  const graph = rawFunctions.map((f) => {
    const calls = new Set();
    for (const otherName of knownNames) {
      if (otherName === f.name) continue;
      if (new RegExp(`\\b${escapeRegex(otherName)}\\s*\\(`).test(f.body)) {
        calls.add(otherName);
      }
    }

    const touchesDb = DB_MARKERS.some((p) => p.test(f.body));
    const producesOutput = OUTPUT_MARKERS.some((p) => p.test(f.body));
    const route = findRoute(f);

    return {
      name: f.name,
      calls: [...calls],
      is_route_handler: Boolean(route),
      route,
      touches_db: touchesDb,
      produces_output: producesOutput,
    };
  });

  // A real system doesn't start at a random collection of disconnected
  // routes - it starts by running one file, which creates the app, sets
  // up the database connection, and (via `@app.route(...)`-style
  // decorators, which run at *import time*, not per-request) registers
  // every route before a single request ever arrives. If this file looks
  // like that entrypoint, add one synthetic "startup" node wired to every
  // route it registers, so the diagram can be rooted there instead of
  // showing routes as unconnected floating boxes.
  const startupNode = buildStartupNode(content, ext, graph);
  return startupNode ? [startupNode, ...graph] : graph;
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Recognizable database-driver call shapes across the ORMs/drivers the
// rest of this analyzer already understands - deliberately generic (method
// name only, no variable-name matching) since this runs per-function, not
// per-collection.
const DB_MARKERS = [
  /\.(insert_one|insert_many|find_one|update_one|update_many|delete_one|delete_many|aggregate)\s*\(/, // pymongo
  /\.(insertOne|insertMany|findOne|findById|updateOne|updateMany|deleteOne|deleteMany)\s*\(/, // native Mongo driver / Mongoose
  /\.(save|create|query|filter_by|get_or_create)\s*\(/, // generic ORM verbs (Sequelize/TypeORM/Django/SQLAlchemy)
  /\bcursor\.execute\s*\(/, // raw SQL
];

// Recognizable "this is where a response actually goes out" call shapes.
const OUTPUT_MARKERS = [
  /\bjsonify\s*\(/,
  /\brender_template\s*\(/,
  /\bHttpResponse\s*\(/,
  /\bres\.(json|send|render|end)\s*\(/,
  /\bNextResponse\b/,
];

// Recognizable "this file is the one that actually runs the app" shapes -
// deliberately conservative, so a random utility file that happens to
// import Flask/Express somewhere doesn't get treated as the entrypoint.
const ENTRYPOINT_MARKERS = [
  /\bFlask\s*\(\s*__name__/, // Python/Flask
  /\bFastAPI\s*\(/, // Python/FastAPI
  /if\s+__name__\s*==\s*['"]__main__['"]/, // Python's actual run-guard
  /\bexpress\s*\(\s*\)/, // Node/Express
  /\.listen\s*\(\s*(process\.env\.)?[A-Za-z0-9_.]*\s*,?.*\)/, // app.listen(...)
];

// Recognizable "this is where the database connection itself gets set up"
// shapes - separate from DB_MARKERS above, which look for a *query/write*
// call inside a function body, not a one-time connection at startup.
const DB_STARTUP_MARKERS = [
  /\bMongoClient\s*\(/,
  /\bmongoose\.connect\s*\(/,
  /\bcreateConnection\s*\(/,
  /\bnew\s+Sequelize\s*\(/,
  /\bcreate_engine\s*\(/,
];

/**
 * If this file's content looks like the actual app entrypoint (not just
 * some file that happens to mention Flask/Express), returns one synthetic
 * "startup" node wired to every route handler already found in `graph` -
 * modeling the real fact that route-registering decorators/route-table
 * calls run once, when this file is executed, before any request exists.
 * Returns null for every other file, so this never adds noise to a
 * repo's other modules.
 */
function buildStartupNode(content, ext, graph) {
  const looksLikeEntrypoint = ENTRYPOINT_MARKERS.some((p) => p.test(content));
  if (!looksLikeEntrypoint) return null;

  const routeNames = graph.filter((f) => f.is_route_handler).map((f) => f.name);
  if (routeNames.length === 0) return null; // an entrypoint with no routes at all isn't worth its own node

  return {
    name: "__startup__",
    calls: routeNames,
    is_route_handler: false,
    route: null,
    touches_db: DB_STARTUP_MARKERS.some((p) => p.test(content)),
    produces_output: false,
    is_startup: true,
  };
}

/**
 * Splits Python source into top-level-ish function definitions by
 * indentation (a real Python body is always indented deeper than its own
 * `def` line) - good enough without needing a real Python parser. Also
 * captures any `@decorator` lines immediately above each `def`, since
 * that's where Flask/FastAPI route registration lives.
 */
function extractPythonFunctions(content) {
  const lines = content.split("\n");
  const defRegex = /^([ \t]*)def\s+(\w+)\s*\(/;
  const functions = [];

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(defRegex);
    if (!match) continue;
    const indent = match[1].length;
    const name = match[2];

    const decorators = [];
    let d = i - 1;
    while (d >= 0 && lines[d].trim().startsWith("@")) {
      decorators.unshift(lines[d].trim());
      d--;
    }

    const bodyLines = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (line.trim() === "") {
        bodyLines.push(line);
        continue;
      }
      const lineIndent = line.match(/^[ \t]*/)[0].length;
      if (lineIndent <= indent) break;
      bodyLines.push(line);
    }

    functions.push({ name, decorators, body: bodyLines.join("\n") });
  }

  return functions;
}

/**
 * Extracts JS/TS function declarations (`function name(...) {}`), arrow
 * functions assigned to a const (`const name = (...) => {}`), and their
 * bodies via balanced-brace matching - same "good enough for this file's
 * level of analysis" philosophy as the rest of this module.
 */
function extractJsFunctions(content) {
  const functions = [];
  const patterns = [
    /(?:^|\n)\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\(/g,
    /(?:^|\n)\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{/g,
  ];

  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(content)) !== null) {
      const name = match[1];
      const braceStart = content.indexOf("{", regex.lastIndex - 1);
      if (braceStart === -1) continue;
      let depth = 0;
      let end = braceStart;
      for (; end < content.length; end++) {
        if (content[end] === "{") depth++;
        else if (content[end] === "}") {
          depth--;
          if (depth === 0) break;
        }
      }
      functions.push({ name, decorators: [], body: content.slice(braceStart + 1, end) });
    }
  }

  return functions;
}

// Route detection: Python's decorator-above-def (Flask/FastAPI); a bare
// route-registration line naming this same function as its handler is
// deliberately NOT attempted for JS here (app.get('/x', handlerName) with
// an inline anonymous handler is far more common in practice, and can't be
// tied back to a *named* function this way) - JS functions simply come
// back with route: null unless a future pass adds that.
function findRoute(f) {
  for (const dec of f.decorators || []) {
    const match = dec.match(/@\w+\.(get|post|put|delete|patch|route)\s*\(\s*['"`]([^'"`]+)['"`]/i);
    if (match) {
      let method = match[1].toUpperCase();
      if (method === "ROUTE") {
        // Flask's bare @app.route() defaults to GET, but often carries an
        // explicit `methods=[...]` kwarg naming the real one(s).
        const methodsMatch = dec.match(/methods\s*=\s*\[([^\]]*)\]/i);
        method = methodsMatch
          ? methodsMatch[1].replace(/['"` ]/g, "").split(",").filter(Boolean).join("/")
          : "GET/POST";
      }
      return { method, endpoint: match[2] };
    }
  }
  return null;
}

module.exports = extractCallGraph;
