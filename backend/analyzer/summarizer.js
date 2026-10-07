const fs = require("fs");
const path = require("path");

// 1. Primary Bouncer: Looks for deep backend logic
const HIGH_VALUE_PATTERNS = [
  /routes.*\.js$/,
  /controller.*\.js$/,
  /index\.js$/,
  /app\.js$/,
  /main\.py$/,
  /service.*\.js$/,
  /model.*\.js$/,
];

// 2. Fallback Bouncer: Looks for general context if logic is missing
const FALLBACK_PATTERNS = [
  /README\.md$/i,
  /package\.json$/,
  /index\.html$/,
  /docker-compose\.ya?ml$/,
];

// The local LLM (Ollama) is a nice-to-have, not a dependency the rest of
// the scan can be held hostage by. Two problems with the old code made a
// flaky/offline/slow LLM feel like it was breaking the whole feature
// instead of just degrading it:
//   1. No timeout at all - a stalled Ollama request could hang the
//      `await` in analyzer/index.js indefinitely, which stalls the whole
//      /api/analyze request behind it (nothing else in that pipeline
//      would ever "fail fast").
//   2. One failed attempt (a dropped connection, a slow cold-start on
//      Ollama's first request, one malformed JSON response) gave up
//      immediately and fell back to a generic, useless placeholder
//      string ("AI summary unavailable.") even though a second try
//      moments later would very likely have worked.
// Both are fixed here without changing the happy path at all: a healthy
// Ollama on the first try behaves exactly as before.
const LLM_TIMEOUT_MS = 60000; // per attempt - the first attempt gets this full budget, no delay added beforehand
const LLM_MAX_ATTEMPTS = 3; // 1 initial try + 2 retries
const LLM_RETRY_BACKOFF_MS = 3000; // only applied BETWEEN attempts (after a failure), multiplied by attempt number - never before the first try

// async function callOllama(prompt) {
//   let lastError;

//   for (let attempt = 1; attempt <= LLM_MAX_ATTEMPTS; attempt++) {
//     const controller = new AbortController();
//     const timer = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

//     try {
//       const response = await fetch("http://localhost:11434/api/generate", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({
//           model: "mistral", // Remember to keep this matching your downloaded model (e.g., llama3.1)
//           prompt,
//           stream: false,
//           format: "json",
//         }),
//         signal: controller.signal,
//       });

//       if (!response.ok) {
//         const errorData = await response.text();
//         throw new Error(`Ollama Error ${response.status}: ${errorData}`);
//       }

//       const data = await response.json();
//       // A "successful" HTTP response whose body isn't the JSON object we
//       // asked for is still a failure worth retrying (Ollama occasionally
//       // wraps output in prose despite `format: "json"`), not something to
//       // silently pass through as an empty summary.
//       return JSON.parse(data.response.trim());
//     } catch (error) {
//       lastError = error;
//       const reason =
//         error.name === "AbortError"
//           ? `timed out after ${LLM_TIMEOUT_MS}ms`
//           : error.message;
//       console.warn(
//         `⚠️ LLM attempt ${attempt}/${LLM_MAX_ATTEMPTS} failed: ${reason}`,
//       );
//       if (attempt < LLM_MAX_ATTEMPTS) {
//         await new Promise((resolve) =>
//           setTimeout(resolve, LLM_RETRY_BACKOFF_MS * attempt),
//         );
//       }
//     } finally {
//       clearTimeout(timer);
//     }
//   }

//   throw lastError;
// }
class NonRetryableLlmError extends Error {}

async function callGemini(prompt) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    // No point retrying a missing key
    throw new NonRetryableLlmError("GEMINI_API_KEY is not set in backend/.env");
  }
  const model = process.env.GEMINI_MODEL || "gemini-3.5-flash-lite";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  let lastError;

  for (let attempt = 1; attempt <= LLM_MAX_ATTEMPTS; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: prompt }] }],
          generationConfig: { responseMimeType: "application/json" },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorData = await response.text();
        const err = new Error(`Gemini Error ${response.status}: ${errorData}`);
        // 400/401/403/404 = bad request, bad key or wrong model name.
        // Retrying will not fix those. 429 and 5xx are worth retrying.
        if (
          response.status >= 400 &&
          response.status < 500 &&
          response.status !== 429
        ) {
          throw new NonRetryableLlmError(err.message);
        }
        throw err;
      }

      const data = await response.json();
      const parts = data?.candidates?.[0]?.content?.parts || [];
      const text = parts
        .filter((p) => !p.thought && typeof p.text === "string")
        .map((p) => p.text)
        .join("")
        .trim();

      if (!text) {
        const reason =
          data?.promptFeedback?.blockReason ||
          data?.candidates?.[0]?.finishReason ||
          "empty response";
        throw new Error(`Gemini returned no text (${reason})`);
      }

      // Same rule as before: a reply that isn't valid JSON counts as a failure and is retried
      return JSON.parse(text);
    } catch (error) {
      lastError = error;
      if (error instanceof NonRetryableLlmError) throw error;

      const reason =
        error.name === "AbortError"
          ? `timed out after ${LLM_TIMEOUT_MS}ms`
          : error.message;
      console.warn(
        `⚠️ LLM attempt ${attempt}/${LLM_MAX_ATTEMPTS} failed: ${reason}`,
      );
      if (attempt < LLM_MAX_ATTEMPTS) {
        await new Promise((resolve) =>
          setTimeout(resolve, LLM_RETRY_BACKOFF_MS * attempt),
        );
      }
    } finally {
      clearTimeout(timer);
    }
  }

  throw lastError;
}

/** Builds a real, specific summary straight from data the rest of the
 *  analyzer already computed (languages, frameworks, API routes, DB
 *  models, symbol counts) - no LLM involved. Used whenever Ollama is
 *  offline, times out, or returns something unusable, so a scan's
 *  "Summary" and "Business Logic" panels always say something concrete
 *  about *this* repository instead of a generic apology. Also used to
 *  fill in any individual field the LLM left blank. */
function buildFallbackSummary(repoName, context = {}) {
  const {
    languages = [],
    frameworks = [],
    apiEndpoints = [],
    databaseModels = [],
    classes = [],
    functions = [],
    totalFiles = 0,
  } = context;

  const langPart = languages.length
    ? `written primarily in ${languages.slice(0, 3).join(", ")}`
    : "with no clearly dominant language detected";
  const fwPart = frameworks.length
    ? `, using ${frameworks.slice(0, 4).join(", ")}`
    : "";
  const filesPart = totalFiles ? `${totalFiles}-file ` : "";

  const basic = `'${repoName}' is a ${filesPart}project ${langPart}${fwPart}.`;

  const logicParts = [];

  if (apiEndpoints.length) {
    const methods = [
      ...new Set(apiEndpoints.map((e) => e.method).filter(Boolean)),
    ].join("/");
    const sample = apiEndpoints
      .slice(0, 3)
      .map((e) => `${e.method} ${e.endpoint}`)
      .join(", ");
    logicParts.push(
      `Exposes ${apiEndpoints.length} API endpoint${apiEndpoints.length === 1 ? "" : "s"}${
        methods ? ` (${methods})` : ""
      }${sample ? `, e.g. ${sample}` : ""}.`,
    );
  }

  if (databaseModels.length) {
    const tableNames = databaseModels
      .map((m) => m.table_name || m.tableName)
      .filter(Boolean)
      .slice(0, 5)
      .join(", ");
    logicParts.push(
      `Persists data through ${databaseModels.length} database model${databaseModels.length === 1 ? "" : "s"}${
        tableNames ? ` (${tableNames})` : ""
      }.`,
    );
  }

  if (classes.length || functions.length) {
    logicParts.push(
      `Core logic spans ${classes.length} class${classes.length === 1 ? "" : "es"} and ${functions.length} top-level function${
        functions.length === 1 ? "" : "s"
      }.`,
    );
  }

  if (logicParts.length === 0) {
    logicParts.push(
      "No API routes, database models, or class/function symbols were detected in the scanned files - this may be a static/frontend-only, config, or documentation-heavy repository.",
    );
  }

  logicParts.push(
    "(Generated from static scan data - the local LLM was unavailable or returned an unusable response.)",
  );

  return { basic, logic: logicParts.join(" ") };
}

async function summarizeBusinessLogic(filePaths, repoName, context = {}) {
  let hasCoreLogic = true;

  // Try to find the heavy logic files first
  let filesToAnalyze = filePaths.filter((filePath) =>
    HIGH_VALUE_PATTERNS.some((pattern) => pattern.test(filePath)),
  );

  // If no backend logic is found, trigger the fallback mechanism
  if (filesToAnalyze.length === 0) {
    hasCoreLogic = false;
    filesToAnalyze = filePaths.filter((filePath) =>
      FALLBACK_PATTERNS.some((pattern) => pattern.test(filePath)),
    );

    // If it STILL can't find anything (a very weird repo), just grab the first 3 files
    if (filesToAnalyze.length === 0 && filePaths.length > 0) {
      filesToAnalyze = filePaths.slice(0, 3);
    }
  }

  // If the repository is completely empty
  if (filesToAnalyze.length === 0) {
    return {
      basic: "Empty repository.",
      logic: "No files found to analyze.",
    };
  }

  // Computed up front and unconditionally - this is what gets returned if
  // the LLM never comes through, and also what backfills any individual
  // field ("basic_summary"/"business_logic") the LLM left blank.
  const fallback = buildFallbackSummary(repoName, context);

  // 3. Dynamic Prompt Construction
  let prompt = `You are a senior software architect analyzing a repository named '${repoName}'.\n`;
  prompt += `Analyze the following files and output a strict JSON object with EXACTLY two keys:\n`;
  prompt += `- "basic_summary": A 1-2 sentence high-level description of what this project does.\n`;

  // Tell the AI how to handle the logic section based on what files we found
  if (hasCoreLogic) {
    prompt += `- "business_logic": A detailed explanation of the primary workflows, API routes, and data management.\n\n`;
  } else {
    prompt += `- "business_logic": State that deep backend logic files were not found, but describe the overall structure, dependencies, or purpose based on the configuration or README files provided.\n\n`;
  }

  filesToAnalyze.forEach((file) => {
    try {
      const content = fs.readFileSync(file, "utf-8");
      const truncatedContent =
        content.length > 4000
          ? content.slice(0, 4000) + "\n...[TRUNCATED]"
          : content;
      prompt += `--- FILE: ${path.basename(file)} ---\n${truncatedContent}\n\n`;
    } catch (error) {
      console.warn(`⚠️ Warning: Could not read ${file} for summarization.`);
    }
  });

  try {
    console.log(
      `🤖 Sending ${filesToAnalyze.length} files to local LLM for JSON analysis...`,
    );

    const parsedAIResponse = await callGemini(prompt);

    // Trust the LLM's own wording when it actually gave us a non-empty
    // string for a field; otherwise use the static fallback for just that
    // field rather than downgrading the whole result to placeholder text.
    const basic =
      typeof parsedAIResponse.basic_summary === "string" &&
      parsedAIResponse.basic_summary.trim()
        ? parsedAIResponse.basic_summary.trim()
        : fallback.basic;
    const logic =
      typeof parsedAIResponse.business_logic === "string" &&
      parsedAIResponse.business_logic.trim()
        ? parsedAIResponse.business_logic.trim()
        : fallback.logic;

    return { basic, logic };
  } catch (error) {
    console.error(
      `❌ LLM unavailable after ${LLM_MAX_ATTEMPTS} attempts - using static fallback summary.`,
    );
    console.error(error.message);
    return fallback;
  }
}

module.exports = summarizeBusinessLogic;
module.exports.buildFallbackSummary = buildFallbackSummary;
