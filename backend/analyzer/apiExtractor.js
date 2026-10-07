const fs = require("fs");
const path = require("path");
const { toLongPath } = require("../utils/longPath");

function extractApiRoutes(filePath) {
  let content = "";
  try {
    content = fs.readFileSync(toLongPath(filePath), "utf-8");
  } catch (error) {
    return [];
  }

  const fileName = path.basename(filePath);
  const ext = path.extname(filePath).toLowerCase();
  const routes = [];
  const seen = new Set();

  function addRoute(method, endpoint, framework) {
    if (!endpoint) return;
    endpoint = String(endpoint).trim();
    if (!endpoint) return;
    method = String(method || "ANY").toUpperCase();
    const key = `${method}|${endpoint}|${framework}`;
    if (seen.has(key)) return;
    seen.add(key);
    routes.push({ method, endpoint, file: fileName, framework });
  }

  function scan(regex, onMatch) {
    let match;
    while ((match = regex.exec(content)) !== null) {
      onMatch(match);
      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  const JS_EXTS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);

  if (JS_EXTS.has(ext)) {
    scan(
      /\b(?:app|router|fastify|server)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      (m) => addRoute(m[1], m[2], "Express/Node"),
    );

    scan(
      /@(Get|Post|Put|Delete|Patch|Options|Head|All)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g,
      (m) => addRoute(m[1], m[2] || "/", "NestJS"),
    );

    scan(/type\s+(Query|Mutation|Subscription)\s*\{([^}]*)\}/g, (m) => {
      const opType = m[1];
      const fields = m[2];
      const fieldRegex = /(\w+)\s*(?:\([^)]*\))?\s*:/g;
      let fieldMatch;
      while ((fieldMatch = fieldRegex.exec(fields)) !== null) {
        addRoute(opType, fieldMatch[1], "GraphQL");
      }
    });
  }

  if (ext === ".graphql" || ext === ".gql") {
    const typeRegex = /type\s+(Query|Mutation|Subscription)\s*\{([^}]*)\}/g;
    let typeMatch;
    while ((typeMatch = typeRegex.exec(content)) !== null) {
      const opType = typeMatch[1];
      const fieldRegex = /(\w+)\s*(?:\([^)]*\))?\s*:/g;
      let fieldMatch;
      while ((fieldMatch = fieldRegex.exec(typeMatch[2])) !== null) {
        addRoute(opType, fieldMatch[1], "GraphQL");
      }
    }
  }

  if (ext === ".py") {
    scan(
      /@(?:\w+)\.(get|post|put|delete|patch|route)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      (m) => {
        let method = m[1].toUpperCase();
        if (method === "ROUTE") method = "GET/POST"; // Flask's bare @app.route default
        addRoute(method, m[2], "Flask/FastAPI");
      },
    );

    const looksLikeDjangoUrls =
      fileName === "urls.py" || /django/i.test(content);
    if (looksLikeDjangoUrls) {
      scan(/\b(?:path|re_path|url)\s*\(\s*r?['"`]([^'"`]*)['"`]/g, (m) =>
        addRoute("ROUTE", m[1], "Django"),
      );
    }
  }

  if (ext === ".rb") {
    const looksLikeRailsRoutes =
      fileName === "routes.rb" || /Rails\.application\.routes/.test(content);
    if (looksLikeRailsRoutes) {
      scan(/\b(get|post|put|patch|delete)\s+['"]([^'"]+)['"]/g, (m) =>
        addRoute(m[1], m[2], "Rails"),
      );
      scan(/\bresources?\s+:(\w+)/g, (m) =>
        addRoute("RESOURCE", `/${m[1]}`, "Rails"),
      );
    }
  }

  if (ext === ".java") {
    const mappingToMethod = {
      GetMapping: "GET",
      PostMapping: "POST",
      PutMapping: "PUT",
      DeleteMapping: "DELETE",
      PatchMapping: "PATCH",
    };
    scan(
      /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*(?:value\s*=\s*)?['"]([^'"]*)['"]/g,
      (m) => addRoute(mappingToMethod[m[1]], m[2] || "/", "Spring"),
    );
    scan(/@RequestMapping\s*\(([^)]*)\)/g, (m) => {
      const args = m[1];
      const pathMatch =
        args.match(/(?:value|path)\s*=\s*['"]([^'"]*)['"]/) ||
        args.match(/^\s*['"]([^'"]*)['"]/);
      const methodMatch = args.match(/RequestMethod\.(\w+)/);
      addRoute(
        methodMatch ? methodMatch[1] : "REQUEST",
        pathMatch ? pathMatch[1] : "/",
        "Spring",
      );
    });
  }

  if (ext === ".go") {
    // Gin / Echo style: router.GET("/users", handler), e.POST("/login", h)
    scan(
      /\b\w+\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any)\s*\(\s*"([^"]+)"/g,
      (m) => addRoute(m[1], m[2], "Go (Gin/Echo)"),
    );

    // net/http & Gorilla Mux: http.HandleFunc("/users", h) / router.HandleFunc("/users", h)
    scan(/\bHandleFunc\s*\(\s*"([^"]+)"/g, (m) =>
      addRoute("HANDLER", m[1], "Go (net/http)"),
    );
  }

  if (ext === ".php") {
    scan(
      /Route::(get|post|put|delete|patch|any|resource)\s*\(\s*['"]([^'"]+)['"]/gi,
      (m) => addRoute(m[1], m[2], "Laravel"),
    );
  }

  if (ext === ".cs") {
    scan(
      /\[Http(Get|Post|Put|Delete|Patch)(?:\s*\(\s*"([^"]*)"\s*\))?\]/g,
      (m) => addRoute(m[1], m[2] || "/", "ASP.NET Core"),
    );
    scan(/\[Route\s*\(\s*"([^"]+)"\s*\)\]/g, (m) =>
      addRoute("ROUTE", m[1], "ASP.NET Core"),
    );
  }

  if (ext === ".proto") {
    scan(/\brpc\s+(\w+)\s*\(/g, (m) => addRoute("RPC", m[1], "gRPC"));
  }

  return routes;
}

module.exports = extractApiRoutes;
