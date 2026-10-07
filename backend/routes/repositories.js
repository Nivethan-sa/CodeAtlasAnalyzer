const express = require("express");
const db = require("../db/queries");
const { isSafeGithubUsername } = require("../utils/validate");

const router = express.Router();

// --- GET /api/repositories/:owner/:repo/history -----------------------
// Every past scan's score for one repository, oldest first - this is
// what draws the trend sparkline once a repo has been audited more
// than once.
router.get("/:owner/:repo/history", async (req, res) => {
  try {
    const { owner, repo } = req.params;
    if (!isSafeGithubUsername(owner)) {
      return res.status(400).json({ error: "Invalid owner." });
    }

    const fullName = `${owner}/${repo}`;
    const history = await db.findScanHistoryForRepository(fullName);

    res.json({ repository: fullName, scans: history.length, history });
  } catch (error) {
    console.error("❌ Repository history error:", error.message);
    res.status(500).json({ error: "Failed to load repository history." });
  }
});

module.exports = router;
