// All database access goes through this file - same public API as before
// (every function name/signature callers already use), now backed by
// MongoDB instead of node:sqlite. Every function is now async (returns a
// Promise) since a Mongo call is a network round-trip; every call site
// across the app was updated to `await` these.

const crypto = require("crypto");
const { getDb } = require("./mongoClient");

function newId() {
  return crypto.randomUUID();
}

function col(name) {
  return getDb().collection(name);
}

// --- Doc -> JS object mappers --------------------------------------------
// Documents are written with the exact camelCase shape the rest of the app
// expects, so mapping here is mostly just renaming Mongo's `_id` to the
// `id` field already used everywhere (JWTs, URLs, etc.) - there's no
// snake_case or JSON-text translation layer to maintain the way the old
// SQL schema needed.

function mapUser(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    email: doc.email,
    passwordHash: doc.passwordHash,
    username: doc.username,
    // Collected at signup (see routes/auth.js's /register) so a brand new
    // account can analyze repos with its own identity right away, instead
    // of needing a separate trip to a settings screen first.
    githubToken: doc.githubToken || null,
    githubUsername: doc.githubUsername || null,
    // Set only for accounts created with / linked to "Continue with Google"
    // (see utils/googleAuth.js). googleId is Google's stable `sub` claim -
    // the email can change, the sub never does.
    googleId: doc.googleId || null,
    avatarUrl: doc.avatarUrl || null,
    // This user's own JWT signing secret (see utils/jwtKey.js) - generated
    // automatically at signup, combined with the server-wide JWT_SECRET
    // pepper to sign/verify THIS user's session tokens specifically. Never
    // typed in by a person (a weak typed value would make sessions
    // forgeable) - only ever rotated, which signs that one account out
    // everywhere without touching anyone else's session.
    jwtSecret: doc.jwtSecret || null,
    jwtSecretRotatedAt: doc.jwtSecretRotatedAt || doc.createdAt || null,
    createdAt: doc.createdAt,
  };
}

function mapRepository(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    owner: doc.owner,
    name: doc.name,
    fullName: doc.fullName,
    htmlUrl: doc.htmlUrl,
    description: doc.description,
    primaryLanguage: doc.primaryLanguage,
    firstScannedAt: doc.firstScannedAt,
    lastScannedAt: doc.lastScannedAt,
  };
}

function mapScanDoc(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    repositoryId: doc.repositoryId,
    userId: doc.userId,
    commitSha: doc.commitSha,
    filesScanned: doc.filesScanned,
    healthScore: doc.healthScore,
    healthGrade: doc.healthGrade,
    // Kept as JSON *strings* (not parsed back into objects) because
    // routes/scans.js's toAnalyzePayload() calls JSON.parse on these
    // fields itself (via its own safeParse helper) - this mirrors exactly
    // what a SQLite TEXT column handed back, so that consumer needed zero
    // changes when the storage engine underneath it changed.
    languages: doc.languages,
    frameworks: doc.frameworks,
    strengths: doc.strengths,
    warnings: doc.warnings,
    basicSummary: doc.basicSummary,
    businessLogic: doc.businessLogic,
    astTargetFile: doc.astTargetFile,
    astTree: doc.astTree,
    scannedFiles: doc.scannedFiles,
    classes: doc.classes,
    functions: doc.functions,
    repoTree: doc.repoTree,
    branches: doc.branches,
    branchHierarchy: doc.branchHierarchy,
    commits: doc.commits,
    pullRequests: doc.pullRequests,
    repoMetadata: doc.repoMetadata,
    contributors: doc.contributors,
    callGraph: doc.callGraph,
    createdAt: doc.createdAt,
    // Embedded sub-documents (native arrays of objects, not JSON strings) -
    // these used to live in their own SQL tables (vulnerabilities,
    // api_endpoints, database_models) joined in by hydrateScan(); Mongo's
    // document model lets them just live inside the scan document itself.
    vulnerabilities: doc.vulnerabilities || [],
    apiEndpoints: doc.apiEndpoints || [],
    databaseModels: doc.databaseModels || [],
  };
}

/** Attaches the parent repository to a bare scan document, mirroring the
 * shape the rest of the app expects (this used to be a SQL JOIN). */
async function hydrateScan(scanDoc) {
  if (!scanDoc) return null;
  const scan = mapScanDoc(scanDoc);
  const repoDoc = await col("repositories").findOne({ _id: scan.repositoryId });
  scan.repository = mapRepository(repoDoc);
  return scan;
}

// --- Users ---------------------------------------------------------------

async function createUser({
  email,
  passwordHash,
  username,
  githubToken,
  githubUsername,
  googleId,
  avatarUrl,
}) {
  const id = newId();
  const now = new Date();
  await col("users").insertOne({
    _id: id,
    email,
    // null for Google-only accounts - they have no password to check.
    passwordHash: passwordHash || null,
    username: username || null,
    githubToken: githubToken || null,
    githubUsername: githubUsername || null,
    // Only written when present so the sparse unique index on googleId
    // (db/mongoClient.js) ignores password accounts instead of colliding
    // on a shared null.
    ...(googleId ? { googleId } : {}),
    ...(avatarUrl ? { avatarUrl } : {}),
    jwtSecret: crypto.randomBytes(32).toString("hex"),
    jwtSecretRotatedAt: now,
    createdAt: now,
  });
  return findUserById(id);
}

/** Rotates a user's personal JWT signing secret, invalidating every session
 *  token previously issued to them (and only them). */
async function regenerateUserJwtSecret(id) {
  await col("users").updateOne(
    { _id: id },
    {
      $set: {
        jwtSecret: crypto.randomBytes(32).toString("hex"),
        jwtSecretRotatedAt: new Date(),
      },
    },
  );
  return findUserById(id);
}

/** Updates a user's personal GitHub token/username from Settings. Passing
 *  null for either clears it (falling back to no personal value). */
async function updateUserGithub(id, { githubToken, githubUsername } = {}) {
  const update = {};
  if (githubToken !== undefined) update.githubToken = githubToken || null;
  if (githubUsername !== undefined)
    update.githubUsername = githubUsername || null;
  if (Object.keys(update).length) {
    await col("users").updateOne({ _id: id }, { $set: update });
  }
  return findUserById(id);
}

async function findUserByEmail(email) {
  return mapUser(await col("users").findOne({ email }));
}

async function findUserByGoogleId(googleId) {
  if (!googleId) return null;
  return mapUser(await col("users").findOne({ googleId }));
}

async function findUserById(id) {
  return mapUser(await col("users").findOne({ _id: id }));
}

// --- Repositories ----------------------------------------------------------

async function upsertRepository({
  owner,
  name,
  fullName,
  htmlUrl,
  description,
  primaryLanguage,
}) {
  const repos = col("repositories");
  const existing = await repos.findOne({ fullName });

  if (existing) {
    await repos.updateOne(
      { _id: existing._id },
      {
        $set: {
          description: description || null,
          primaryLanguage: primaryLanguage || null,
          lastScannedAt: new Date(),
        },
      },
    );
    return mapRepository(await repos.findOne({ _id: existing._id }));
  }

  const id = newId();
  const now = new Date();
  await repos.insertOne({
    _id: id,
    owner,
    name,
    fullName,
    htmlUrl: htmlUrl || null,
    description: description || null,
    primaryLanguage: primaryLanguage || null,
    firstScannedAt: now,
    lastScannedAt: now,
  });
  return mapRepository(await repos.findOne({ _id: id }));
}

async function findRepositoryByFullName(fullName) {
  return mapRepository(await col("repositories").findOne({ fullName }));
}

// --- Scans -----------------------------------------------------------------

// A single insertOne is already atomic, and everything a scan needs
// (vulnerabilities, api endpoints, database models) is embedded in this
// one document instead of split across child tables - so there's no
// multi-statement transaction to wrap the way the old SQL version needed
// (BEGIN / COMMIT / ROLLBACK by hand).
async function createScan(scan) {
  const id = newId();
  const doc = {
    _id: id,
    repositoryId: scan.repositoryId,
    userId: scan.userId || null,
    commitSha: scan.commitSha || null,
    filesScanned: scan.filesScanned || 0,
    healthScore: scan.healthScore,
    healthGrade: scan.healthGrade,
    languages: scan.languages,
    frameworks: scan.frameworks,
    strengths: scan.strengths,
    warnings: scan.warnings,
    basicSummary: scan.basicSummary || null,
    businessLogic: scan.businessLogic || null,
    astTargetFile: scan.astTargetFile || null,
    astTree: scan.astTree || null,
    scannedFiles: scan.scannedFiles || "[]",
    classes: scan.classes || "[]",
    functions: scan.functions || "[]",
    repoTree: scan.repoTree || null,
    branches: scan.branches || null,
    branchHierarchy: scan.branchHierarchy || null,
    commits: scan.commits || null,
    pullRequests: scan.pullRequests || null,
    repoMetadata: scan.repoMetadata || null,
    contributors: scan.contributors || null,
    callGraph: scan.callGraph || null,
    vulnerabilities: (scan.vulnerabilities || []).map((v) => ({
      id: newId(),
      type: v.type,
      severity: v.severity,
      file: v.file,
      line: String(v.line),
      snippet: v.snippet,
    })),
    apiEndpoints: (scan.apiEndpoints || []).map((e) => ({
      id: newId(),
      method: e.method,
      endpoint: e.endpoint,
      file: e.file,
    })),
    databaseModels: (scan.databaseModels || []).map((m) => ({
      id: newId(),
      ormType: m.ormType,
      tableName: m.tableName,
      // Feature: ER diagram / system flow - best-effort, may be empty for
      // ORMs/patterns the extractor couldn't confidently parse.
      fields: Array.isArray(m.fields) ? m.fields : [],
      relationships: Array.isArray(m.relationships) ? m.relationships : [],
    })),
    createdAt: new Date(),
  };

  await col("scans").insertOne(doc);
  return hydrateScan(doc);
}

async function findScanById(id) {
  return hydrateScan(await col("scans").findOne({ _id: id }));
}

async function findLatestScanForRepository(fullName) {
  const repo = await col("repositories").findOne({ fullName });
  if (!repo) return null;
  const scanDoc = await col("scans")
    .find({ repositoryId: repo._id })
    .sort({ createdAt: -1 })
    .limit(1)
    .next();
  return hydrateScan(scanDoc);
}

async function listScans({ scope, userId, limit }) {
  const filter = scope === "mine" ? { userId } : {};
  const scanDocs = await col("scans")
    .find(filter)
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();
  if (scanDocs.length === 0) return [];

  // One extra query to fetch every referenced repository in a single
  // round-trip (via $in), instead of a JOIN - avoids an N+1 query pattern
  // for what used to be a single SQL statement.
  const repoIds = [...new Set(scanDocs.map((s) => s.repositoryId))];
  const repoDocs = await col("repositories")
    .find({ _id: { $in: repoIds } })
    .toArray();
  const repoById = new Map(repoDocs.map((r) => [r._id, r]));

  return scanDocs.map((s) => {
    const repo = repoById.get(s.repositoryId);
    return {
      id: s._id,
      repository: repo?.fullName || "unknown/unknown",
      htmlUrl: repo?.htmlUrl || null,
      healthScore: s.healthScore,
      healthGrade: s.healthGrade,
      filesScanned: s.filesScanned,
      createdAt: s.createdAt,
    };
  });
}

async function deleteScan(id) {
  await col("scans").deleteOne({ _id: id });
  await col("scanSources").deleteOne({ _id: id });
}

async function findScanHistoryForRepository(fullName) {
  const repo = await col("repositories").findOne({ fullName });
  if (!repo) return [];
  const scanDocs = await col("scans")
    .find({ repositoryId: repo._id })
    .sort({ createdAt: 1 })
    .toArray();
  return scanDocs.map((s) => ({
    id: s._id,
    healthScore: s.healthScore,
    healthGrade: s.healthGrade,
    commitSha: s.commitSha,
    createdAt: s.createdAt,
  }));
}

// --- Chat messages -----------------------------------------------------------

async function createChatMessage({ scanId, userId, role, content }) {
  await col("chatMessages").insertOne({
    _id: newId(),
    scanId,
    userId: userId || null,
    role,
    content,
    createdAt: new Date(),
  });
}

// Most recent messages for one scan (oldest first) so the chat agent can
// follow up on earlier questions instead of treating each one in isolation.
async function listRecentChatMessages(scanId, userId, limit = 10) {
  const docs = await col("chatMessages")
    .find({ scanId, userId: userId || null })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();
  return docs.reverse().map((d) => ({ role: d.role, content: d.content }));
}

// --- Scan source code (what the chat agent reads) ------------------------------
// Kept in its own collection, keyed by the scan id, so the big code snapshot
// never bloats the scan document that the history/list endpoints load.

async function saveScanSource(scanId, snapshot) {
  await col("scanSources").replaceOne(
    { _id: scanId },
    { _id: scanId, ...snapshot, createdAt: new Date() },
    { upsert: true },
  );
}

async function findScanSource(scanId) {
  return col("scanSources").findOne({ _id: scanId });
}

// --- Clone jobs (temp_repos audit trail) --------------------------------------
// Tracks each attempt to clone a repo into backend/temp_repos, independent
// of whether the scan that triggered it ultimately succeeds. The cloned
// files themselves are still cleaned up after each scan - this collection
// only keeps the *record* of what happened (timing, status, error), so a
// stuck/slow/failing clone is visible after the fact via /api/clone-jobs
// instead of only in server logs at the moment it happened.

function mapCloneJob(doc) {
  if (!doc) return null;
  return {
    id: doc._id,
    repositoryFullName: doc.repositoryFullName,
    tempPath: doc.tempPath,
    status: doc.status,
    errorMessage: doc.errorMessage,
    durationMs: doc.durationMs,
    startedAt: doc.startedAt,
    finishedAt: doc.finishedAt,
  };
}

async function createCloneJob({ repositoryFullName, tempPath }) {
  const id = newId();
  await col("cloneJobs").insertOne({
    _id: id,
    repositoryFullName,
    tempPath,
    status: "cloning",
    errorMessage: null,
    durationMs: null,
    startedAt: new Date(),
    finishedAt: null,
  });
  return id;
}

async function finishCloneJob(id, { status, errorMessage, durationMs }) {
  await col("cloneJobs").updateOne(
    { _id: id },
    {
      $set: {
        status,
        errorMessage: errorMessage || null,
        durationMs: durationMs ?? null,
        finishedAt: new Date(),
      },
    },
  );
}

async function listCloneJobs({ limit = 50, repositoryFullName = null } = {}) {
  const filter = repositoryFullName ? { repositoryFullName } : {};
  const docs = await col("cloneJobs")
    .find(filter)
    .sort({ startedAt: -1 })
    .limit(limit)
    .toArray();
  return docs.map(mapCloneJob);
}

const { connect, close } = require("./mongoClient");

module.exports = {
  connect,
  close,
  createUser,
  regenerateUserJwtSecret,
  updateUserGithub,
  findUserByEmail,
  findUserByGoogleId,
  findUserById,
  upsertRepository,
  findRepositoryByFullName,
  createScan,
  findScanById,
  findLatestScanForRepository,
  listScans,
  deleteScan,
  findScanHistoryForRepository,
  createChatMessage,
  listRecentChatMessages,
  saveScanSource,
  findScanSource,
  createCloneJob,
  finishCloneJob,
  listCloneJobs,
};
