// MongoDB connection singleton. Replaces the previous node:sqlite-backed
// db/client.js - same job (hand every query function in db/queries.js a
// live database handle), different engine.
//
// Configure via backend/.env:
//   MONGODB_URI=mongodb://127.0.0.1:27017        (local)
//   MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net  (Atlas)
//   MONGODB_DB_NAME=codeatlas
//
// connect() must be awaited once at server startup (see server.js) before
// any request touches the database - unlike node:sqlite, which opened the
// file synchronously and was ready the instant it was required, a Mongo
// connection is asynchronous and needs a network round-trip to establish.

const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017";
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || "codeatlas";

let client = null;
let db = null;
let connectingPromise = null;

/** Indexes mirror the ones the old schema.sql declared (unique email/repo
 * full name, plus lookup/sort indexes on the fields queries.js filters or
 * sorts by most often). createIndex is a no-op if the index already
 * exists, so this is safe to run on every startup. */
async function ensureIndexes(database) {
  await Promise.all([
    database.collection("users").createIndex({ email: 1 }, { unique: true }),
    database.collection("users").createIndex({ googleId: 1 }, { unique: true, sparse: true }),
    database.collection("repositories").createIndex({ fullName: 1 }, { unique: true }),
    database.collection("repositories").createIndex({ owner: 1 }),
    database.collection("scans").createIndex({ repositoryId: 1 }),
    database.collection("scans").createIndex({ userId: 1 }),
    database.collection("scans").createIndex({ createdAt: -1 }),
    database.collection("chatMessages").createIndex({ scanId: 1 }),
    database.collection("cloneJobs").createIndex({ repositoryFullName: 1 }),
    database.collection("cloneJobs").createIndex({ startedAt: -1 }),
  ]);
}

async function connect() {
  if (db) return db;
  if (connectingPromise) return connectingPromise;

  connectingPromise = (async () => {
    client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
    await client.connect();
    const database = client.db(MONGODB_DB_NAME);
    await ensureIndexes(database);
    db = database;
    console.log(`🗄️  Connected to MongoDB (${MONGODB_DB_NAME})`);
    return db;
  })().catch((error) => {
    // Let the next call retry instead of caching a permanent failure -
    // useful if Mongo was still starting up when the app first tried.
    connectingPromise = null;
    throw error;
  });

  return connectingPromise;
}

/** Synchronous accessor used by every query in db/queries.js. Throws
 * loudly if something queries the database before connect() has resolved,
 * rather than silently hitting a null reference. */
function getDb() {
  if (!db) {
    throw new Error(
      "MongoDB is not connected yet - call db.connect() during server startup before handling requests.",
    );
  }
  return db;
}

async function close() {
  if (client) await client.close();
  client = null;
  db = null;
  connectingPromise = null;
}

module.exports = { connect, getDb, close };
