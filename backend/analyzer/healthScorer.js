function generateHealthScore(scanData) {
  let score = 100;
  const warnings = [];
  const strengths = [];

  if (
    !scanData.description ||
    scanData.description === "Description not found"
  ) {
    score -= 15;
    warnings.push("No repository description found in package.json or README.");
  } else {
    strengths.push("Good documentation practices (Description found).");
  }

  if (
    scanData.totalFiles > 20 &&
    scanData.classes.length === 0 &&
    scanData.functions.length < 10
  ) {
    score -= 10;
    warnings.push(
      "High file count but low structural symbols. Potential unstructured code.",
    );
  }

  const hasDatabase =
    scanData.database_models.length > 0 ||
    scanData.technologies.some((t) =>
      ["MongoDB", "PostgreSQL", "MySQL"].includes(t),
    );
  const hasAuth = scanData.technologies.some((t) =>
    ["JWT", "Passport", "Bcrypt"].includes(t),
  );

  if (hasDatabase && !hasAuth) {
    score -= 20;
    warnings.push(
      "CRITICAL: Database models detected, but no authentication libraries found.",
    );
  } else if (hasDatabase && hasAuth) {
    strengths.push(
      "Secure architecture: Database paired with authentication libraries.",
    );
  }

  if (scanData.technologies.length === 0 && scanData.totalFiles > 5) {
    score -= 10;
    warnings.push("No standard frameworks or libraries detected.");
  }

  // NEW: DevSecOps Vulnerability Check
  if (scanData.security_leaks && scanData.security_leaks.length > 0) {
    score -= 40; // Massive penalty for leaking secrets
    scanData.security_leaks.forEach((leak) => {
      warnings.push(
        `[${leak.severity}] Leaked ${leak.type} in ${leak.file} (Line ${leak.line})`,
      );
    });
  } else {
    strengths.push("No hardcoded secrets or API keys detected in core files.");
  }

  let grade = "F";
  if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";

  return {
    score: score,
    grade: grade,
    strengths: strengths,
    warnings: warnings,
  };
}

module.exports = generateHealthScore;
