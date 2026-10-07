const analyzeRepository = require("./analyzer");
const fs = require("fs");
const path = require("path");

async function runAudit() {
  // In GitHub Actions, GITHUB_WORKSPACE is the folder where the code is checked out
  const repoPath = process.env.GITHUB_WORKSPACE || process.cwd();
  const repoName = process.env.GITHUB_REPOSITORY || "local-scan";

  console.log(`\n🚀 Starting CodeAtlas Headless Audit on: ${repoName}`);

  try {
    // Run the core engine (This uses the defensive programming we built earlier!)
    const result = await analyzeRepository(repoPath, repoName);

    // Build a beautifully formatted Markdown report for the GitHub PR comment
    let report = `## 🛡️ CodeAtlas DevSecOps Audit\n\n`;
    report += `**Health Grade:** ${result.health_audit.grade} (${result.health_audit.score}/100)\n`;
    report += `**Files Scanned:** ${result.analysis.files}\n\n`;

    // Security Section
    if (result.analysis.security_vulnerabilities.length > 0) {
      report += `### ⚠️ Critical Security Alerts (${result.analysis.security_vulnerabilities.length})\n`;
      result.analysis.security_vulnerabilities.forEach((leak) => {
        report += `- **${leak.type}** found in \`${leak.file}\`\n`;
      });
    } else {
      report += `### ✅ Security Audit: Passed\nNo hardcoded secrets or vulnerable dependencies detected.\n`;
    }

    // Architecture Section
    report += `\n### 🏗️ Architecture & API\n`;
    report += `- **Frameworks:** ${result.analysis.frameworks.join(", ") || "None detected"}\n`;
    report += `- **Databases:** ${result.analysis.database_tables.length > 0 ? result.analysis.database_tables.map((t) => t.table_name).join(", ") : "None detected"}\n`;
    report += `- **API Routes:** ${result.analysis.api_endpoints.length} endpoints mapped.\n`;

    // Note on AI: GitHub cloud runners don't have Ollama installed,
    // so the AI summary will gracefully fallback to "Unavailable" thanks to our previous fix.

    // Save the report to a file so the GitHub Action can read it
    fs.writeFileSync(path.join(repoPath, "codeatlas-report.md"), report);

    console.log(`✅ Audit complete. Report saved to codeatlas-report.md`);

    // If the score is an F, we fail the pipeline to prevent bad code from being merged!
    if (result.health_audit.grade === "F") {
      console.error("❌ Health Grade is F. Failing the pipeline.");
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (error) {
    console.error("❌ Headless Scan Failed:", error);
    process.exit(1);
  }
}

runAudit();
