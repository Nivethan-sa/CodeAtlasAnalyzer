const fs = require("fs");
const path = require("path");
const { parseJsSymbols } = require("./jsSymbols");
const { toLongPath } = require("../utils/longPath");

// Safely load the JSON registry
let techMap;
try {
  techMap = JSON.parse(
    fs.readFileSync(path.join(__dirname, "technologyMap.json"), "utf-8"),
  );
} catch (error) {
  console.error("❌ Extractor failed to load technologyMap.json");
  process.exit(1);
}

// Acorn can only parse plain JS (no JSX, no TypeScript type syntax), so we
// only attempt the real-AST path for these extensions and fall back to the
// regex heuristic below for everything else - including .jsx/.ts/.tsx files
// that fail to parse for that reason.
const ACORN_JS_EXTENSIONS = new Set([".js", ".mjs", ".cjs"]);

/** Flattens the rich {name, type, detail, line, children} nodes from
 * jsSymbols.js down to the plain name lists this module has always
 * returned, so nothing downstream (scanner.js, healthScorer.js, the
 * frontend) needs to change shape. Class methods are kept too, qualified
 * as ClassName.methodName so they don't collide with top-level functions. */
function flattenJsSymbols(nodes) {
  const symbols = { classes: [], functions: [] };
  for (const node of nodes) {
    if (node.type === "class") {
      symbols.classes.push(node.name);
      for (const child of node.children || []) {
        if (child.type === "method") symbols.functions.push(`${node.name}.${child.name}`);
      }
    } else if (node.type === "function") {
      symbols.functions.push(node.name);
    }
  }
  return symbols;
}

/**
 * Universally extracts classes and functions. For plain JS/CJS/MJS files
 * this does a real Acorn-based AST walk (via jsSymbols.js), which catches
 * far more shapes than a regex ever could - class methods, functions
 * assigned to `module.exports.x`, object-literal methods, and so on. Every
 * other language (and any JS file Acorn can't parse) falls back to the
 * regex patterns defined in technologyMap.json.
 * @param {string} filePath - Absolute path to the file.
 * @returns {Object} - Arrays of found classes and functions.
 */
function extractSymbols(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const symbols = { classes: [], functions: [] };

  if (ACORN_JS_EXTENSIONS.has(ext)) {
    try {
      const content = fs.readFileSync(toLongPath(filePath), "utf-8");
      return flattenJsSymbols(parseJsSymbols(content));
    } catch (error) {
      // Syntax Acorn couldn't handle - fall through to the regex path
      // below instead of returning nothing for this file.
    }
  }

  // 1. Find the language rules based on the file extension
  const langKey = Object.keys(techMap.languages).find((lang) =>
    techMap.languages[lang].extensions.includes(ext),
  );

  // If we don't support the language, just return empty arrays safely
  if (!langKey) return symbols;

  const rules = techMap.languages[langKey];

  try {
    const content = fs.readFileSync(toLongPath(filePath), "utf-8");

    // 2. Extract Classes dynamically
    if (rules.classPattern) {
      const classRegex = new RegExp(rules.classPattern, "gm");
      let match;
      while ((match = classRegex.exec(content)) !== null) {
        symbols.classes.push(match[1]);
      }
    }

    // 3. Extract Functions dynamically
    if (rules.functionPattern) {
      const funcRegex = new RegExp(rules.functionPattern, "gm");
      let match;
      while ((match = funcRegex.exec(content)) !== null) {
        // match[1] handles standard functions, match[2] handles JS arrow functions
        const funcName = match[1] || match[2];
        if (funcName) symbols.functions.push(funcName);
      }
    }
  } catch (error) {
    console.warn(`⚠️ Warning: Extractor could not read ${filePath}`);
  }

  return symbols;
}

module.exports = extractSymbols;
