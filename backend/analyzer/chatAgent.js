const Sentry = require("@sentry/node");
const { formatSnapshotForPrompt } = require("./codeSnapshot");

/**
 * Sends a conversational query to Gemini, armed with the repository's scan
 * results AND its actual source code, so "Atlas" can answer questions about
 * what the code really does (e.g. "how does login work?").
 * Streams tokens back via onToken for a fast perceived response.
 *
 * @param {string} question - The user's chat message.
 * @param {Object} context - The scan payload (see toAnalyzePayload).
 * @param {Function} [onToken] - Called with each streamed chunk of text.
 * @param {Object} [options]
 * @param {Object} [options.sourceSnapshot] - { files, totalFiles, ... } from codeSnapshot.js
 * @param {Array}  [options.history] - earlier [{role: "user"|"assistant", content}] messages
 * @returns {Promise<string>} The full reply.
 */

const CHAT_TIMEOUT_MS = 90000; // large code prompts take longer to start streaming
const CHAT_MAX_ATTEMPTS = 2; // 1 try + 1 retry (only if nothing was streamed yet)
const CHAT_MAX_OUTPUT_TOKENS = 2048;
const MAX_LIST_ITEMS = 150;

// Cache the static part of the prompt per scan so we don't rebuild a huge
// string for every message. Keyed by scan id (NOT repo name - two scans of
// the same repo have different code).
const _systemPromptCache = new Map();

function limited(list, mapFn) {
  const items = (list || []).slice(0, MAX_LIST_ITEMS).map(mapFn);
  const extra = (list || []).length - items.length;
  return items.join("\n") + (extra > 0 ? `\n...and ${extra} more` : "");
}

function buildSystemPrompt(context, sourceSnapshot) {
  const cacheKey = `${context.scan_id || context.repository}:${sourceSnapshot ? sourceSnapshot.includedFiles : 0}`;
  if (_systemPromptCache.has(cacheKey)) return _systemPromptCache.get(cacheKey);

  const a = context.analysis || {};
  let prompt = `You are "Atlas," a senior AI developer assistant. You are answering questions about a repository named '${context.repository}'.\n\n`;
  prompt += `SCAN DATA extracted from this repository:\n`;
  prompt += `- Languages: ${(a.languages || []).join(", ") || "unknown"}\n`;
  prompt += `- Frameworks: ${(a.frameworks || []).join(", ") || "unknown"}\n`;
  prompt += `- Files scanned: ${a.files ?? "unknown"}\n`;
  prompt += `- AI Architectural Summary: ${(a.basic_summary || "").slice(0, 1500)}\n`;
  prompt += `- Deep Business Logic: ${(a.business_logic || "").slice(0, 3000)}\n`;

  if (a.database_tables && a.database_tables.length > 0) {
    prompt += `- Database Tables: ${a.database_tables.map((t) => t.table_name).join(", ")}\n`;
  }
  if (a.api_endpoints && a.api_endpoints.length > 0) {
    prompt += `\nAPI ENDPOINTS:\n${limited(a.api_endpoints, (e) => `${e.method} ${e.endpoint} (${e.file})`)}\n`;
  }
  if (a.security_vulnerabilities && a.security_vulnerabilities.length > 0) {
    prompt += `\nSECURITY FINDINGS (${a.security_vulnerabilities.length}):\n${limited(
      a.security_vulnerabilities,
      (v) => `- [${v.severity || "?"}] ${v.type} in ${v.file || "?"}${v.line ? `:${v.line}` : ""}`,
    )}\n`;
  }

  const code = formatSnapshotForPrompt(sourceSnapshot);
  if (code) {
    prompt += `\n${code}\n`;
  } else {
    prompt += `\nNOTE: The raw source code is NOT available for this scan (it was scanned before code access existed). Only the scan data above can be used - say so if the question needs the actual code, and suggest re-running the scan.\n`;
  }

  _systemPromptCache.set(cacheKey, prompt);
  if (_systemPromptCache.size > 20) {
    _systemPromptCache.delete(_systemPromptCache.keys().next().value);
  }
  return prompt;
}

const ANSWER_RULES =
  `\n\nRULES: Answer the user's question directly and accurately using ONLY the scan data and source code above. ` +
  `Refer to specific file paths (and function names) when explaining how something works. ` +
  `If the answer isn't in the provided code, say so instead of guessing. Never invent code you haven't seen.`;

class NonRetryableChatError extends Error {}

// What the person sees when Gemini can't answer. Specific enough to act on
// (this is a self-hosted tool - the operator is the one who can fix it),
// without echoing raw API error bodies into the chat window.
function friendlyFailureMessage(error) {
  const model = process.env.GEMINI_MODEL || "gemini-3.5-flash-lite";
  if (error.name === "AbortError") {
    return "The AI took too long to answer. Try again, or lower CHAT_CODE_CHAR_BUDGET in backend/.env to send less code.";
  }
  if (/GEMINI_API_KEY is not set/.test(error.message)) {
    return "The chat assistant isn't configured: add GEMINI_API_KEY to backend/.env and restart the server.";
  }
  switch (error.httpStatus) {
    case 400:
      return "Gemini rejected the request (400). If the repository is very large, lower CHAT_CODE_CHAR_BUDGET in backend/.env. Details are in the server console.";
    case 401:
    case 403:
      return "Gemini rejected the API key. Check GEMINI_API_KEY in backend/.env and restart the server.";
    case 404:
      return `Gemini model "${model}" was not found. Check GEMINI_MODEL in backend/.env.`;
    case 429:
      return "Gemini rate limit or quota reached. Wait a minute and try again, or lower CHAT_CODE_CHAR_BUDGET in backend/.env.";
    default:
      return "I'm having trouble reaching the AI service right now. Please try again in a moment.";
  }
}

// Gemini needs the conversation to start with and end on a "user" turn.
function buildContents(question, history) {
  const turns = [];
  for (const m of history || []) {
    if (!m || !m.content || (m.role !== "user" && m.role !== "assistant")) continue;
    const role = m.role === "assistant" ? "model" : "user";
    const last = turns[turns.length - 1];
    if (last && last.role === role) {
      last.parts[0].text += `\n${m.content}`; // merge consecutive same-role turns
    } else {
      turns.push({ role, parts: [{ text: m.content }] });
    }
  }
  while (turns.length && turns[0].role !== "user") turns.shift();
  const last = turns[turns.length - 1];
  if (last && last.role === "user") {
    last.parts[0].text += `\n${question}`;
  } else {
    turns.push({ role: "user", parts: [{ text: question }] });
  }
  return turns;
}

async function streamFromGemini(systemPrompt, question, history, onToken) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new NonRetryableChatError("GEMINI_API_KEY is not set in backend/.env");
  }
  const model = process.env.GEMINI_MODEL || "gemini-3.5-flash-lite";
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CHAT_TIMEOUT_MS);
  let full = "";

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: systemPrompt + ANSWER_RULES }] },
        contents: buildContents(question, history),
        generationConfig: { maxOutputTokens: CHAT_MAX_OUTPUT_TOKENS },
      }),
      signal: controller.signal,
    });

    if (!response.ok || !response.body) {
      const errorText = await response.text().catch(() => "");
      const message = `Gemini Error ${response.status}: ${errorText.slice(0, 500)}`;
      // 400/401/403/404 won't be fixed by retrying; 429 and 5xx might be
      const httpError =
        response.status >= 400 && response.status < 500 && response.status !== 429
          ? new NonRetryableChatError(message)
          : new Error(message);
      httpError.httpStatus = response.status;
      throw httpError;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let finishReason = null;

    const handleLine = (rawLine) => {
      const line = rawLine.trim();
      if (!line.startsWith("data:")) return;
      const json = line.slice(5).trim();
      if (!json || json === "[DONE]") return;
      let obj;
      try {
        obj = JSON.parse(json);
      } catch {
        return; // skip malformed partial line
      }
      const candidate = obj.candidates?.[0];
      if (candidate?.finishReason) finishReason = candidate.finishReason;
      for (const part of candidate?.content?.parts || []) {
        if (part.thought || typeof part.text !== "string" || !part.text) continue;
        full += part.text;
        if (onToken) onToken(part.text);
      }
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop(); // keep the incomplete trailing line for the next loop
      lines.forEach(handleLine);
    }
    if (buffer.trim()) handleLine(buffer);

    if (!full.trim()) {
      throw new Error(`Gemini returned no text (${finishReason || "empty response"})`);
    }
    return full.trim();
  } catch (error) {
    // Remember how much was already streamed so the caller doesn't retry mid-answer
    error.partialLength = full.length;
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function askRepoChatbot(question, context, onToken, options = {}) {
  const systemPrompt = buildSystemPrompt(context, options.sourceSnapshot);

  for (let attempt = 1; attempt <= CHAT_MAX_ATTEMPTS; attempt++) {
    try {
      return await streamFromGemini(systemPrompt, question, options.history, onToken);
    } catch (error) {
      const reason =
        error.name === "AbortError" ? `timed out after ${CHAT_TIMEOUT_MS}ms` : error.message;
      console.error(`❌ Chat Agent Error (attempt ${attempt}/${CHAT_MAX_ATTEMPTS}): ${reason}`);

      const canRetry =
        attempt < CHAT_MAX_ATTEMPTS &&
        !(error instanceof NonRetryableChatError) &&
        !error.partialLength; // never retry after tokens were already sent to the user

      if (canRetry) {
        await new Promise((resolve) => setTimeout(resolve, 1500 * attempt));
        continue;
      }

      // Final failure: report to Sentry (this used to be swallowed silently).
      Sentry.captureException(error, {
        tags: { area: "chat-agent", model: process.env.GEMINI_MODEL || "default" },
      });

      const fallback = friendlyFailureMessage(error);
      if (onToken && !error.partialLength) onToken(fallback);
      return error.partialLength ? "" : fallback;
    }
  }
}

module.exports = askRepoChatbot;
