const { runDiagramCode } = require("../utils/pythonDiagram");

const DIAGRAM_TIMEOUT_MS = 60000;
const MAX_TABLES = 40;
const MAX_FIELDS = 25;
const MAX_ENDPOINTS = 60;
const MAX_FUNCTIONS = 80;

/** Compact, size-capped slice of the scan - only what the two diagrams need. */
function buildDiagramContext(analysis) {
  const a = analysis || {};
  const tables = (a.database_tables || []).slice(0, MAX_TABLES).map((t) => ({
    table: t.table_name,
    source: t.database_type,
    fields: (t.fields || []).slice(0, MAX_FIELDS).map((f) => ({
      name: f.name,
      type: f.type,
      ...(f.isForeignKey ? { foreignKey: true } : {}),
    })),
    relationships: (t.relationships || []).map((r) => ({
      field: r.field,
      to: r.targetTable,
      type: r.type,
      ...(r.inferred ? { inferred: true } : {}),
    })),
  }));
  const endpoints = (a.api_endpoints || []).slice(0, MAX_ENDPOINTS).map((e) => ({
    method: e.method,
    path: e.endpoint,
    file: e.file,
  }));
  const functions = (a.call_graph || []).slice(0, MAX_FUNCTIONS).map((f) => ({
    name: f.name,
    file: f.file,
    calls: f.calls || [],
    ...(f.is_startup ? { startup: true } : {}),
    ...(f.is_route_handler && f.route ? { route: `${f.route.method} ${f.route.endpoint}` } : {}),
    ...(f.touches_db ? { touchesDatabase: true } : {}),
    ...(f.produces_output ? { sendsResponse: true } : {}),
  }));
  return {
    languages: a.languages || [],
    frameworks: a.frameworks || [],
    tables,
    endpoints,
    functions,
  };
}

const COMMON_RULES = `
You write a short Python script that builds a diagram with the \`graphviz\` package's builder API.
HARD RULES - the script is validated and anything else is rejected:
- The ONLY import allowed is: from graphviz import Digraph
- No other imports, no file/network/OS access, no classes, no dunder names (like __name__), no exec/eval/open.
- Use plain Python (loops, lists, dicts, f-strings) over data you write out literally in the script.
- Build one Digraph called dot, then finish with: print(dot.source)
- Do NOT call dot.render() or dot.view().
- Use ONLY the facts in the JSON below. Never invent tables, fields, endpoints, functions or relationships.
- Keep it readable: set rankdir, a legible fontname="Helvetica", and consistent colours; escape quotes in labels.
- Output ONLY the Python code. No markdown fences, no explanation.
`;

function erPrompt(ctx) {
  return `${COMMON_RULES}
TASK: an Entity-Relationship (ER) diagram of this repository's data model.
- One node per table, drawn as a record/HTML-table card: table name as a bold header, then one row per field with its type; mark primary keys (like _id / id) with "PK" and foreign keys with "FK".
- One edge per relationship (field -> target table), labelled with the field name, with crow's-foot style arrowheads (arrowhead="crow" for the "many" side, "tee" for the "one" side, dir="both" where needed).
- relationships marked inferred:true are naming guesses: draw them dashed (style="dashed") and add "(inferred)" to the label.
- Tables with no relationships still get drawn.
- Use rankdir="LR" (or "TB" for very small schemas) and shape="plain" or "none" with HTML-like labels (strings starting with < and ending with >).

REPOSITORY DATA (JSON):
${JSON.stringify(ctx.tables)}
`;
}

function flowPrompt(ctx) {
  return `${COMMON_RULES}
TASK: a SYSTEM FLOW diagram showing how a request moves through this application.
- Layer it top-to-bottom (rankdir="TB"): the app entrypoint/startup (if any) -> API endpoints (rounded "METHOD /path" nodes) -> the functions they call (from "calls") -> database tables, plus a "Response" node for functions that send a response.
- If "functions" is empty, link each endpoint to the table whose name matches its URL (e.g. /api/users -> users); if there is nothing to link, draw the tables grouped by their "source" in clusters and say so in a graph label. Do not make links up.
- Edges from a function to the database mean touchesDatabase:true (dashed, orange). Edges to "Response" mean sendsResponse:true (green).
- Table-to-table relationships (the "relationships" inside tables) may be shown as thin dashed grey edges.
- Give each kind of node a distinct colour/shape and add a small legend as a cluster or a graph label.

REPOSITORY DATA (JSON):
${JSON.stringify({ endpoints: ctx.endpoints, functions: ctx.functions, tables: ctx.tables.map((t) => ({ table: t.table, source: t.source, relationships: t.relationships })) })}
`;
}

function stripFences(text) {
  let t = String(text || "").trim();
  const fenced = t.match(/```(?:python|py)?\s*\n([\s\S]*?)```/i);
  if (fenced) t = fenced[1];
  return t.replace(/^```(?:python|py)?/i, "").replace(/```\s*$/, "").trim();
}

async function callGemini(prompt) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    const e = new Error("GEMINI_API_KEY is not set in backend/.env");
    e.userMessage = "Add GEMINI_API_KEY to backend/.env and restart the server to generate AI diagrams.";
    throw e;
  }
  const model = process.env.GEMINI_MODEL || "gemini-3.5-flash-lite";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DIAGRAM_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
      body: JSON.stringify({
        contents: [{ role: "user", parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.2, maxOutputTokens: 8192 },
      }),
      signal: controller.signal,
    });
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      const e = new Error(`Gemini Error ${response.status}: ${body.slice(0, 300)}`);
      e.httpStatus = response.status;
      throw e;
    }
    const data = await response.json();
    const text = (data.candidates?.[0]?.content?.parts || [])
      .filter((p) => !p.thought && typeof p.text === "string")
      .map((p) => p.text)
      .join("");
    if (!text.trim()) throw new Error("Gemini returned no text");
    return stripFences(text);
  } finally {
    clearTimeout(timer);
  }
}

function friendlyError(error) {
  if (error.userMessage) return error.userMessage;
  if (error.name === "AbortError") return "Gemini took too long to answer. Try again.";
  switch (error.httpStatus) {
    case 401:
    case 403: return "Gemini rejected the API key. Check GEMINI_API_KEY in backend/.env.";
    case 404: return `Gemini model "${process.env.GEMINI_MODEL || "gemini-3.5-flash-lite"}" was not found. Check GEMINI_MODEL in backend/.env.`;
    case 429: return "Gemini rate limit or quota reached. Wait a minute and try again.";
    default: return error.message || "Could not generate the diagram.";
  }
}

/**
 * Asks Gemini for a Python script, runs it, and - if it fails - gives Gemini
 * the error once so it can repair its own script.
 * @returns {{code?: string, dot?: string, error?: string}}
 */
async function generateOne(prompt, { generate = callGemini, run = runDiagramCode } = {}) {
  let code = "";
  try {
    code = await generate(prompt);
    let result = await run(code);
    if (result.ok) return { code, dot: result.dot };

    // Python missing on the server won't be fixed by a rewrite.
    if (/Python 3 was not found/.test(result.error)) return { code, error: result.error };

    const repairPrompt = `${prompt}\n\nYour previous script:\n${code}\n\nIt failed with this error:\n${result.error}\n\nReturn a corrected, complete script that follows every rule. Output only the code.`;
    code = await generate(repairPrompt);
    result = await run(code);
    if (result.ok) return { code, dot: result.dot };
    return { code, error: result.error };
  } catch (error) {
    return { code: code || undefined, error: friendlyError(error) };
  }
}

/** Generates both diagrams in parallel. Always resolves. */
async function generateDiagrams(analysis, deps) {
  const ctx = buildDiagramContext(analysis);
  if (ctx.tables.length === 0) {
    return { er: { error: "No database tables were detected, so there is nothing to diagram." }, flow: { error: "No database tables were detected, so there is nothing to diagram." } };
  }
  const [er, flow] = await Promise.all([generateOne(erPrompt(ctx), deps), generateOne(flowPrompt(ctx), deps)]);
  return { er, flow };
}

module.exports = { generateDiagrams, generateOne, buildDiagramContext, stripFences, erPrompt, flowPrompt };
