const fs = require("fs");
const path = require("path");
const { toLongPath } = require("../utils/longPath");
const { parseJsSymbols } = require("./jsSymbols");

// Acorn only understands plain JS, so JSX/TS files fall back to the
// heuristic brace-based parser below if a real parse fails.
const ACORN_EXTENSIONS = [".js", ".mjs", ".cjs"];
const JSX_TS_EXTENSIONS = [".jsx", ".ts", ".tsx"];
const INDENT_EXTENSIONS = [".py", ".rb"];
const SUPPORTED_EXTENSIONS = [
  ...ACORN_EXTENSIONS,
  ...JSX_TS_EXTENSIONS,
  ...INDENT_EXTENSIONS,
  ".java", ".go", ".rs", ".php", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs",
];

const MAX_SOURCE_LENGTH = 200_000; // don't choke on huge generated/vendored files
const MAX_TREE_NODES = 450; // keep the rendered tree readable, even for big repos

/**
 * Structural tree for indentation-based languages (Python, Ruby). Not a real
 * AST - it walks the source line by line and nests any line that opens a
 * block (def/class/if/for/...) under whichever block is currently open at a
 * shallower indent level. Good enough to visualize a file's actual shape
 * without needing a full per-language grammar.
 */
function parseIndentationBased(code, ext) {
  const lines = code.split(/\r?\n/);
  const root = { name: "Module", type: "block", detail: "Module", line: null, children: [] };
  const stack = [{ indent: -1, node: root }];

  const keywordPattern =
    ext === ".py"
      ? /^\s*(def|class|if|elif|else|for|while|try|except|finally|with)\b/
      : /^\s*(def|class|module|if|elsif|else|unless|for|while|until|begin|rescue|ensure|case|when)\b/;

  lines.forEach((rawLine, idx) => {
    if (!rawLine.trim() || rawLine.trim().startsWith("#")) return;
    if (!keywordPattern.test(rawLine)) return;

    const indent = rawLine.match(/^\s*/)[0].replace(/\t/g, "    ").length;
    const trimmed = rawLine.trim();

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
      stack.pop();
    }

    let label = trimmed.replace(/:$/, "");
    if (label.length > 60) label = label.slice(0, 57) + "...";

    const kindMatch = trimmed.match(/^(def|class|module)\b/);
    const node = {
      name: label,
      type: kindMatch ? kindMatch[1] : "block",
      detail: label,
      line: idx + 1,
      children: [],
    };
    stack[stack.length - 1].node.children.push(node);
    stack.push({ indent, node });
  });

  return root;
}

// Header patterns that mark a block as a class-like construct, across
// Java/C#/PHP ("class"/"interface"/"enum"), Go/Rust ("struct"/"trait"/
// "impl"), and C/C++ ("struct"/"class"/"union").
const CLASS_HEADER = /(^|[\s*])(class|interface|struct|enum|trait|impl|union)\s+[A-Za-z_$]/;

// Go's `type Name struct { ... }` / `type Name interface { ... }` puts the
// struct/interface keyword *after* the name, so it needs its own pattern.
const GO_TYPE_HEADER = /^type\s+[A-Za-z_]\w*\s+(struct|interface)\b/;

// Control-flow keywords that produce a `{` block but aren't a function or
// class - these must NOT be misclassified as functions just because they
// contain parentheses (e.g. `if (x > 0)`).
const CONTROL_HEADER = /^(if|else|for|foreach|while|switch|catch|try|finally|do)\b/;

// A function/method header has an identifier immediately followed by a
// parameter list - deliberately permissive about what comes before (return
// types, modifiers, receivers like Go's `(s *Sample)`) and after (return
// types/arrows, Go's multi-value `(int, error)`, `throws`/`where` clauses,
// `const`/`noexcept` qualifiers), since those vary a lot across languages.
const FUNCTION_HEADER = /[A-Za-z_$][\w$]*\s*\(/;

/** Classifies a brace-block header as "class", "method"/"function", or a
 * generic "block" (control-flow, plain scope, object literal, ...), so
 * every supported language - not just JS - gets real class/function nodes
 * instead of an undifferentiated block tree. */
function classifyHeader(header, parentType) {
  const h = header.trim();
  if (CLASS_HEADER.test(h) || GO_TYPE_HEADER.test(h)) return "class";
  if (CONTROL_HEADER.test(h)) return "block";
  if (FUNCTION_HEADER.test(h)) {
    return parentType === "class" ? "method" : "function";
  }
  return "block";
}

/**
 * Structural tree for brace-delimited languages (Java, Go, Rust, PHP,
 * C/C++/C#, and a reasonable fallback for anything else, including
 * JSX/TS files that Acorn can't parse). Walks the source character by
 * character, tracking string/comment state so braces inside a string or
 * comment don't get mistaken for real block delimiters, and labels each
 * block with whatever text preceded its opening `{` (typically a function
 * signature, class name, or control-flow condition) - classifying it as a
 * class, method/function, or generic block via classifyHeader() above.
 */
function parseBraceBased(code) {
  const root = { name: "File", type: "block", detail: "File", line: null, children: [] };
  const stack = [root];
  let buffer = "";
  let inString = null;
  let inLineComment = false;
  let inBlockComment = false;
  let line = 1;

  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const next = code[i + 1];
    if (ch === "\n") line++;

    if (inLineComment) {
      if (ch === "\n") inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (inString) {
      if (ch === "\\") {
        i++;
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }

    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      inString = ch;
      continue;
    }

    if (ch === "{") {
      let header = buffer.trim().split("\n").pop().trim().replace(/^[,;]+/, "").trim();
      if (!header) header = "block";
      const fullHeader = header;
      if (header.length > 60) header = header.slice(0, 57) + "...";
      const parent = stack[stack.length - 1];
      const type = classifyHeader(fullHeader, parent.type);
      const node = { name: header, type, detail: fullHeader, line, children: [] };
      parent.children.push(node);
      stack.push(node);
      buffer = "";
      continue;
    }
    if (ch === "}") {
      if (stack.length > 1) stack.pop();
      buffer = "";
      continue;
    }

    buffer += ch;
  }

  return root;
}

/** Prunes a tree to a total node budget so the rendered diagram stays
 * readable, replacing any overflow at each level with a single
 * "N more" placeholder rather than silently truncating. */
function capTree(root, maxNodes = MAX_TREE_NODES) {
  let count = 1;
  function walk(node) {
    if (!node.children || node.children.length === 0) return;
    const kept = [];
    for (const child of node.children) {
      if (count >= maxNodes) break;
      count++;
      kept.push(child);
      walk(child);
    }
    if (kept.length < node.children.length) {
      const hiddenCount = node.children.length - kept.length;
      kept.push({
        name: `… ${hiddenCount} more`,
        type: "truncated",
        detail: `${hiddenCount} more item(s) not shown (node budget reached)`,
        line: null,
        children: [],
      });
    }
    node.children = kept;
  }
  walk(root);
  return root;
}

/** Builds the node list for a single file: real class/function symbols via
 * Acorn for plain JS, or a heuristic block tree for everything else
 * (including JS-family files Acorn couldn't parse, e.g. JSX/TS syntax). */
function buildFileChildren(code, ext) {
  if (ACORN_EXTENSIONS.includes(ext)) {
    try {
      return parseJsSymbols(code);
    } catch (error) {
      return parseBraceBased(code).children;
    }
  }
  if (JSX_TS_EXTENSIONS.includes(ext)) {
    // Try the real parser first anyway - plenty of .ts/.tsx files in the
    // wild are actually plain-enough JS to parse fine.
    try {
      return parseJsSymbols(code);
    } catch (error) {
      return parseBraceBased(code).children;
    }
  }
  if (INDENT_EXTENSIONS.includes(ext)) {
    return parseIndentationBased(code, ext).children;
  }
  return parseBraceBased(code).children;
}

/** Reads and parses one file into a {name, type, detail, children} node,
 * or returns null if the file isn't a supported/readable source file. */
function buildFileNode(filePath, relPath) {
  const ext = path.extname(filePath).toLowerCase();
  if (!SUPPORTED_EXTENSIONS.includes(ext) || filePath.includes(".min.")) return null;

  let code;
  try {
    code = fs.readFileSync(toLongPath(filePath), "utf-8");
  } catch {
    return null;
  }
  if (code.length > MAX_SOURCE_LENGTH) code = code.slice(0, MAX_SOURCE_LENGTH);

  const fileName = relPath.split("/").pop();
  const children = buildFileChildren(code, ext);

  return {
    name: fileName,
    type: "file",
    detail: `${relPath} (${children.length} symbol${children.length === 1 ? "" : "s"} found)`,
    line: null,
    children,
  };
}

/**
 * Groups every eligible file in the repo into a directory tree, so the AST
 * view reflects the whole codebase rather than a single arbitrarily-picked
 * file. Each directory becomes a node, each file becomes a node under its
 * directory, and each file's classes/functions (or, for non-JS languages,
 * heuristic blocks) become that file's children.
 */
function buildRepoTree(filePaths, repoRoot) {
  const root = {
    name: path.basename(repoRoot) || "repository",
    type: "root",
    detail: "Repository root",
    line: null,
    children: [],
  };
  const dirNodes = new Map([["", root]]);

  function getDirNode(dirRelPath) {
    if (dirNodes.has(dirRelPath)) return dirNodes.get(dirRelPath);
    const parts = dirRelPath.split("/");
    const parentPath = parts.slice(0, -1).join("/");
    const parentNode = getDirNode(parentPath);
    const dirName = parts[parts.length - 1];
    const node = {
      name: dirName,
      type: "directory",
      detail: `Directory: ${dirRelPath}`,
      line: null,
      children: [],
    };
    parentNode.children.push(node);
    dirNodes.set(dirRelPath, node);
    return node;
  }

  let filesIncluded = 0;
  for (const filePath of filePaths) {
    const relPath = path.relative(repoRoot, filePath).split(path.sep).join("/");
    if (relPath.startsWith("..")) continue; // outside repoRoot - skip defensively

    const fileNode = buildFileNode(filePath, relPath);
    if (!fileNode) continue;

    filesIncluded++;
    const dirRelPath = relPath.split("/").slice(0, -1).join("/");
    getDirNode(dirRelPath).children.push(fileNode);
  }

  return { root, filesIncluded };
}

/**
 * Walks every eligible file in the repository (not just one) and builds a
 * single nested tree: directories -> files -> their classes/functions (or,
 * for non-JS languages, a heuristic structural block tree). Real Acorn ASTs
 * back the JS/CJS/MJS nodes; every other language uses a best-effort
 * heuristic parser. The result is capped to a node budget so the rendered
 * diagram stays usable even on large repositories.
 */
function generateAST(filePaths, repoRoot) {
  if (!filePaths || filePaths.length === 0) {
    return { type: "Error", message: "No files found to analyze." };
  }

  const safeRoot = repoRoot || path.dirname(filePaths[0]);
  const { root, filesIncluded } = buildRepoTree(filePaths, safeRoot);

  if (filesIncluded === 0) {
    return {
      type: "Error",
      message: "No suitable source file found for AST generation.",
    };
  }

  capTree(root);

  return {
    target_file: `Whole repository (${filesIncluded} file${filesIncluded === 1 ? "" : "s"} parsed)`,
    tree: root,
  };
}

module.exports = generateAST;
