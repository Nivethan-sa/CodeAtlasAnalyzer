const { scanRepository } = require("./scanner");
const summarizeBusinessLogic = require("./summarizer");
const generateHealthScore = require("./healthScorer");
const auditDependencies = require("./dependencyChecker");
const generateAST = require("./astParser"); // <-- ADD THIS
const buildRepoTree = require("./repoTree");
const { inferCrossTableRelationships } = require("./schemaExtractor");
const fs = require("fs");
const path = require("path");

async function analyzeRepository(repoPath, repoName) {
  // 1. Scan files (with defensive fallback)
  const scanResults = (await scanRepository(repoPath)) || {};

  // Best-effort relationship inference across every table detected in the
  // whole repo (schemaExtractor.js's per-file extraction can't see other
  // files' tables to compare against - this is the one step that needs
  // the complete picture, so it runs once here rather than per-file).
  // Guarded the same way as every other post-processing step below: a bug
  // in the heuristic should mean "no inferred relationships this scan,"
  // never a failed scan.
  try {
    inferCrossTableRelationships(scanResults.database_models || []);
  } catch (error) {
    console.warn(
      "⚠️ Cross-table relationship inference failed:",
      error.message,
    );
  }

  // 2. AI Summarization (Wrapped in a try/catch so Ollama can't crash the
  // server). summarizeBusinessLogic() already retries the local LLM a few
  // times internally and falls back to a summary built from real scan
  // data (languages/frameworks/API routes/DB models/symbol counts) rather
  // than a placeholder string if it's still unavailable after that - this
  // try/catch is only a backstop for a bug in the summarizer itself, not
  // the normal "LLM is offline" path anymore. It reuses that same
  // data-driven fallback (instead of a generic apology) so a scan's
  // Summary/Business Logic panels always describe *this* repository.
  const summaryContext = {
    languages: scanResults.languages || [],
    frameworks: scanResults.technologies || [],
    apiEndpoints: scanResults.api_endpoints || [],
    databaseModels: scanResults.database_models || [],
    classes: scanResults.classes || [],
    functions: scanResults.functions || [],
    totalFiles: scanResults.totalFiles || 0,
  };

  let summary;
  try {
    summary = await summarizeBusinessLogic(
      scanResults.filePaths || [],
      repoName,
      summaryContext,
    );
  } catch (error) {
    console.warn(
      "⚠️ AI Summarizer threw unexpectedly. Using static fallback text.",
      error.message,
    );
    summary = summarizeBusinessLogic.buildFallbackSummary(
      repoName,
      summaryContext,
    );
  }

  // Ensure summary always exists
  summary =
    summary ||
    summarizeBusinessLogic.buildFallbackSummary(repoName, summaryContext);

  // 3. Dependency Check & Security merging
  let totalSecurityAlerts = scanResults.security_leaks || [];
  try {
    const dependencyAlerts = await auditDependencies(repoPath);
    totalSecurityAlerts = [...totalSecurityAlerts, ...dependencyAlerts];
  } catch (error) {
    console.warn("⚠️ Dependency auditor encountered an error.");
  }

  // 4. Description Check
  let detectedDescription = "Description not found";
  const packageJsonPath = path.join(repoPath, "package.json");
  if (fs.existsSync(packageJsonPath)) {
    try {
      const packageData = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
      if (packageData.description)
        detectedDescription = packageData.description;
    } catch (error) {}
  }

  // 5. BULLETPROOF PRE-SCORE DATA
  // Using `|| []` ensures that if a module is outdated or fails, it defaults to an empty array instead of `undefined`, preventing the 'length' crash!
  const preScoreData = {
    totalFiles: scanResults.totalFiles || 0,
    description: detectedDescription,
    technologies: scanResults.technologies || [],
    classes: scanResults.classes || [],
    functions: scanResults.functions || [],
    database_models: scanResults.database_models || [],
    security_leaks: totalSecurityAlerts,
  };

  const healthReport = generateHealthScore(preScoreData);

  // Every other step in this function is already guarded so one module
  // failing can't take out the whole scan (or, worse per the crash-guard
  // note in server.js, the whole server) - this was the one exception.
  // generateAST is also the most complex single piece of analysis code in
  // the project (a different structural parser per language family), so
  // it's the most likely of all of these to hit an edge case on some
  // real-world file it wasn't tested against.
  let astData;
  try {
    astData = generateAST(scanResults.filePaths || [], repoPath);
  } catch (error) {
    console.warn("⚠️ AST generator failed:", error.message);
    astData = { target_file: null, tree: null };
  }

  // Cap how many file paths we ship to the frontend's "Files Accessed"
  // panel - the true count (scanResults.totalFiles) is still reported in
  // full, this just bounds the DOM/JSON size for very large repositories.
  const SCANNED_FILES_DISPLAY_CAP = 500;
  const allScannedFiles = scanResults.scannedFiles || [];
  const scannedFilesForDisplay = allScannedFiles.slice(
    0,
    SCANNED_FILES_DISPLAY_CAP,
  );

  // 6. Repo tree (parent -> child folder/file structure + counts). Built
  // from the *full* scanned file list (not the display-capped slice
  // above), so counts stay accurate even for huge repos.
  let repoTree;
  try {
    repoTree = buildRepoTree(allScannedFiles);
  } catch (error) {
    console.warn("⚠️ Repo tree builder failed.");
    repoTree = { tree: null, total_files: 0, total_folders: 0, max_depth: 0 };
  }

  return {
    repository: repoName,
    description: detectedDescription,
    health_audit: healthReport,
    analysis: {
      files: scanResults.totalFiles || 0,
      scanned_files: scannedFilesForDisplay,
      scanned_files_truncated:
        allScannedFiles.length > SCANNED_FILES_DISPLAY_CAP,
      languages: scanResults.languages || [],
      frameworks: scanResults.technologies || [],
      database_tables: scanResults.database_models || [],
      api_endpoints: scanResults.api_endpoints || [],
      security_vulnerabilities: totalSecurityAlerts,
      ast_structure: astData,
      repo_tree: repoTree,
      architecture_symbols: {
        total_classes: (scanResults.classes || []).length,
        total_functions: (scanResults.functions || []).length,
        classes: scanResults.classes || [],
        functions: scanResults.functions || [],
      },
      call_graph: scanResults.call_graph || [],
      basic_summary: summary.basic || "N/A",
      business_logic: summary.logic || "N/A",
    },
  };
}

module.exports = analyzeRepository;
