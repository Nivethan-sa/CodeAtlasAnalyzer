const acorn = require("acorn");

/** Turns a function's param nodes into a short, human-readable signature
 * fragment like "req, res, next" or "{ id, name }, ...rest". */
function describeParams(params) {
  return (params || [])
    .map((p) => {
      if (!p) return "?";
      switch (p.type) {
        case "Identifier":
          return p.name;
        case "AssignmentPattern":
          return p.left && p.left.name ? `${p.left.name} = …` : "…";
        case "RestElement":
          return p.argument && p.argument.name ? `...${p.argument.name}` : "...rest";
        case "ObjectPattern":
          return "{ … }";
        case "ArrayPattern":
          return "[ … ]";
        default:
          return "?";
      }
    })
    .join(", ");
}

function lineOf(node) {
  return node && node.loc ? node.loc.start.line : null;
}

/**
 * Walks a full Acorn AST and pulls out every class and function-like
 * declaration it can find - not just top-level ones. Each result carries
 * enough detail (kind, params, line number) to make a useful tooltip,
 * rather than just a bare name.
 *
 * Returns a flat-ish list where classes carry their methods as `children`,
 * so a rendered tree can nest them, while everything else (plain
 * functions, arrow functions assigned to a name, exported handlers) comes
 * back as a single-level node.
 */
function collectJsSymbols(root) {
  const nodes = [];

  function pushFunction(name, fnNode, kindLabel) {
    if (!name) return;
    const params = describeParams(fnNode.params);
    nodes.push({
      name,
      type: "function",
      detail: `${kindLabel} ${name}(${params})`,
      line: lineOf(fnNode),
      children: [],
    });
  }

  function pushClass(node) {
    const name = (node.id && node.id.name) || "anonymous";
    const superName =
      node.superClass && node.superClass.name ? ` extends ${node.superClass.name}` : "";
    const methodNodes = [];

    ((node.body && node.body.body) || []).forEach((member) => {
      if (member.type === "MethodDefinition" && member.value) {
        const mName = (member.key && (member.key.name || member.key.value)) || "?";
        const params = describeParams(member.value.params);
        methodNodes.push({
          name: mName,
          type: "method",
          detail: `${member.kind || "method"} ${mName}(${params})`,
          line: lineOf(member),
          children: [],
        });
      } else if (member.type === "PropertyDefinition") {
        const mName = (member.key && (member.key.name || member.key.value)) || "?";
        methodNodes.push({
          name: mName,
          type: "field",
          detail: `field ${mName}`,
          line: lineOf(member),
          children: [],
        });
      }
    });

    nodes.push({
      name,
      type: "class",
      detail: `class ${name}${superName}`,
      line: lineOf(node),
      children: methodNodes,
    });
  }

  function walk(node) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(walk);
      return;
    }

    if (typeof node.type === "string") {
      switch (node.type) {
        case "ClassDeclaration":
        case "ClassExpression":
          pushClass(node);
          break;
        case "FunctionDeclaration":
          pushFunction(node.id && node.id.name, node, "function");
          break;
        case "VariableDeclarator":
          if (
            node.init &&
            (node.init.type === "ArrowFunctionExpression" || node.init.type === "FunctionExpression") &&
            node.id &&
            node.id.name
          ) {
            pushFunction(
              node.id.name,
              node.init,
              node.init.type === "ArrowFunctionExpression" ? "const (arrow)" : "const function",
            );
          }
          break;
        case "AssignmentExpression":
          if (
            node.right &&
            (node.right.type === "ArrowFunctionExpression" || node.right.type === "FunctionExpression")
          ) {
            let name = null;
            if (node.left.type === "Identifier") name = node.left.name;
            else if (node.left.type === "MemberExpression" && node.left.property) {
              name = node.left.property.name || node.left.property.value;
            }
            pushFunction(name, node.right, "exports");
          }
          break;
        case "Property":
          if (
            node.value &&
            (node.value.type === "ArrowFunctionExpression" || node.value.type === "FunctionExpression")
          ) {
            const name = node.key && (node.key.name || node.key.value);
            pushFunction(name, node.value, "method");
          }
          break;
        default:
          break;
      }
    }

    for (const key of Object.keys(node)) {
      if (key === "loc" || key === "start" || key === "end" || key === "range") continue;
      const value = node[key];
      if (value && typeof value === "object") walk(value);
    }
  }

  walk(root);
  return nodes;
}

/** Parses JS/CJS/MJS source with Acorn and returns the symbol list above.
 * Throws if the source uses syntax Acorn can't handle (JSX, TS types,
 * very new proposals) - callers should catch and fall back to a
 * regex-based heuristic in that case. */
function parseJsSymbols(code) {
  const ast = acorn.parse(code, {
    ecmaVersion: "latest",
    sourceType: "module",
    allowReturnOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowAwaitOutsideFunction: true,
  });
  return collectJsSymbols(ast);
}

module.exports = { parseJsSymbols, collectJsSymbols, describeParams, lineOf };
