const fs = require("fs");
const path = require("path");
const { toLongPath } = require("../utils/longPath");

/**
 * Scans a file to detect database models and tables across popular ORMs/ODMs.
 *
 * Each returned model also carries a best-effort `fields[]` and
 * `relationships[]`, used to render an ER diagram and (combined with API
 * endpoints/classes) a system flow diagram in the frontend's Database tab.
 * Neither is guaranteed complete - these are single-pass regexes over
 * source text, not a real parser for five different languages/ORMs - so
 * both default to empty arrays rather than throwing when a model's shape
 * doesn't match the patterns below. A model with `fields: []` still
 * renders fine as a bare table name in the ER diagram.
 *
 * fields[]:        { name, type, isForeignKey }
 * relationships[]: { field, targetTable, type }   (type: "belongsTo" | "hasMany")
 *
 * @param {string} filePath - Absolute path to the file.
 * @returns {Array} - An array of objects containing the ORM type, table name, fields, and relationships.
 */
function extractDatabaseSchemas(filePath) {
  const ext = path.extname(filePath);
  let content = "";

  try {
    content = fs.readFileSync(toLongPath(filePath), "utf-8");
  } catch (error) {
    return [];
  }

  const schemas = [];

  // Grabs the balanced `{ ... }` block starting at the first `{` at or
  // after `startIndex` - good enough for the shallow, mostly-flat object
  // literals these ORMs use for schema/model bodies. Not a real brace
  // parser (doesn't understand strings/comments containing braces), but a
  // best-effort block extraction is exactly the level the rest of this
  // file already operates at.
  function extractBlock(text, startIndex) {
    const openIdx = text.indexOf("{", startIndex);
    if (openIdx === -1) return null;
    let depth = 0;
    for (let i = openIdx; i < text.length; i++) {
      if (text[i] === "{") depth++;
      else if (text[i] === "}") {
        depth--;
        if (depth === 0) return text.slice(openIdx + 1, i);
      }
    }
    return null;
  }

  // Escapes a string for safe interpolation into a `new RegExp(...)` source
  // - used below since collection/db/client variable *names* are pulled out
  // of the source text itself and then fed back into further regexes.
  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  // Given the index of the "(" that opens a call, returns the raw text of
  // its argument list by walking paren depth to the matching ")" - unlike
  // extractBlock, this is bounded to the call itself rather than searching
  // forward for the next unrelated "{", which matters here because a raw
  // insert_one/insertOne call's argument is only sometimes an object
  // literal (and insert_many/insertMany's is an array of them).
  function extractCallArgs(text, openParenIndex) {
    if (text[openParenIndex] !== "(") return null;
    let depth = 0;
    for (let i = openParenIndex; i < text.length; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")") {
        depth--;
        if (depth === 0) return text.slice(openParenIndex + 1, i);
      }
    }
    return null;
  }

  // Best-effort "dict/object literal keys" scan used by the raw-driver
  // detectors below (section 6) - since PyMongo/the native Mongo driver are
  // schemaless, this is the only source of field names available at all.
  // Works unbounded across insert_many's whole `[{...}, {...}]` array (not
  // just the first element) since every key in every element is still a
  // real field on the collection. Matches Python's always-quoted dict keys
  // (`'name': value`), JS's bare-or-quoted object keys (`name: value`), and
  // JS's colon-less shorthand properties (`{ name, email }`) with the same
  // pattern. Requires a key to be immediately preceded by `{` or `,`
  // (skipping whitespace) so it doesn't also pick up a `label: value` pair
  // sitting inside a ternary used as one of the dict's values, and (for the
  // colon-less shorthand form only) requires it to be immediately followed
  // by `,` or `}` so it doesn't mistake a plain array element for one.
  function extractFieldsFromCallArgs(argsText) {
    const fields = [];
    const seen = new Set();
    const keyRegex = /[{,]\s*(?:(\w+)\s*(?::|(?=[,}]))|['"]([^'"]+)['"]\s*:)/g;
    let kMatch;
    while ((kMatch = keyRegex.exec(argsText)) !== null) {
      const name = kMatch[1] || kMatch[2];
      if (name && !seen.has(name)) {
        seen.add(name);
        fields.push({ name, type: "inferred", isForeignKey: false });
      }
    }
    return fields;
  }

  // 1. Mongoose (Node.js / MongoDB)
  // Matches: mongoose.model('User', someSchema). Fields/refs come from the
  // nearest preceding `new mongoose.Schema({ ... })` block, which is how
  // these are written in practice (schema defined just above the model
  // call, or in the same file) - not a perfect association across files,
  // but consistent with how every other pattern here works file-by-file.
  if (content.includes("mongoose")) {
    const schemaBlockRegex = /new\s+mongoose\.Schema\s*\(/g;
    const schemaBlocks = [];
    let sMatch;
    while ((sMatch = schemaBlockRegex.exec(content)) !== null) {
      const block = extractBlock(content, sMatch.index);
      if (block !== null) schemaBlocks.push({ index: sMatch.index, block });
    }

    const mongooseRegex = /mongoose\.model\s*\(\s*['"]([^'"]+)['"]/g;
    let match;
    while ((match = mongooseRegex.exec(content)) !== null) {
      const tableName = match[1];
      const fields = [];
      const relationships = [];

      // Nearest schema block before this model call; fall back to the
      // last one in the file if the model call comes first.
      const candidate =
        [...schemaBlocks].reverse().find((b) => b.index < match.index) ||
        schemaBlocks[schemaBlocks.length - 1];

      if (candidate) {
        // Each top-level `fieldName: { ... type: String, ref: 'Other' ... }`
        // or the shorthand `fieldName: String` form.
        const fieldRegex =
          /(\w+)\s*:\s*(?:\[\s*\{([^{}]*)\}\s*\]|\{([^{}]*)\}|(String|Number|Boolean|Date|Buffer|ObjectId|Mixed|Array))/g;
        let fMatch;
        while ((fMatch = fieldRegex.exec(candidate.block)) !== null) {
          const fieldName = fMatch[1];
          const isArrayOfSubdocs = fMatch[2] !== undefined;
          const inner = isArrayOfSubdocs ? fMatch[2] : fMatch[3];
          const shorthandType = fMatch[4];
          const refMatch = inner && inner.match(/ref\s*:\s*['"]([^'"]+)['"]/);
          const typeMatch = inner && inner.match(/type\s*:\s*([A-Za-z.]+)/);
          const isForeignKey = Boolean(refMatch);
          fields.push({
            name: fieldName,
            type: shorthandType || (typeMatch ? typeMatch[1] : (isForeignKey ? "ObjectId" : "Mixed")),
            isForeignKey,
          });
          if (refMatch) {
            relationships.push({
              field: fieldName,
              targetTable: refMatch[1],
              type: isArrayOfSubdocs ? "hasMany" : "belongsTo",
            });
          }
        }
      }

      schemas.push({ database_type: "Mongoose (NoSQL)", table_name: tableName, fields, relationships });
    }
  }

  // 2. Prisma (Universal)
  // Matches: model User { ... } inside .prisma files
  if (ext === ".prisma") {
    const prismaRegex = /model\s+([A-Za-z0-9_]+)\s*\{/g;
    let match;
    while ((match = prismaRegex.exec(content)) !== null) {
      const tableName = match[1];
      const fields = [];
      const relationships = [];
      const block = extractBlock(content, match.index + match[0].length - 1);
      if (block) {
        const lines = block.split("\n").map((l) => l.trim()).filter(Boolean);
        const scalarTypes = new Set([
          "String", "Int", "Float", "Boolean", "DateTime", "Json", "BigInt", "Bytes", "Decimal",
        ]);
        for (const line of lines) {
          const lineMatch = line.match(/^(\w+)\s+([A-Za-z0-9_]+)(\[\])?\??/);
          if (!lineMatch) continue;
          const [, fieldName, fieldType, isArray] = lineMatch;
          // A relation field's type is another model name (capitalized,
          // not a Prisma scalar) - Prisma itself distinguishes these via
          // its schema compiler; here it's just "not a known scalar type".
          const isRelation = !scalarTypes.has(fieldType) && /^[A-Z]/.test(fieldType);
          fields.push({ name: fieldName, type: fieldType, isForeignKey: isRelation });
          if (isRelation) {
            relationships.push({
              field: fieldName,
              targetTable: fieldType,
              type: isArray ? "hasMany" : "belongsTo",
            });
          }
        }
      }
      schemas.push({ database_type: "Prisma ORM", table_name: tableName, fields, relationships });
    }
  }

  // 3. Sequelize (Node.js / SQL)
  // Matches: sequelize.define('User', { ... })
  if (content.includes("sequelize")) {
    const seqRegex = /sequelize\.define\s*\(\s*['"]([^'"]+)['"]/g;
    let match;
    while ((match = seqRegex.exec(content)) !== null) {
      const tableName = match[1];
      const fields = [];
      const block = extractBlock(content, seqRegex.lastIndex);
      if (block) {
        const fieldRegex = /(\w+)\s*:\s*(?:\{[^{}]*type\s*:\s*)?DataTypes\.([A-Z_]+)/g;
        let fMatch;
        while ((fMatch = fieldRegex.exec(block)) !== null) {
          fields.push({ name: fMatch[1], type: fMatch[2], isForeignKey: false });
        }
      }
      // Associations are usually declared separately, e.g.
      // `User.hasMany(Post)` / `Post.belongsTo(User)` - scan the whole file
      // for any association whose *left-hand* model matches this table.
      const relationships = [];
      const assocRegex = new RegExp(
        `${tableName}\\.(hasMany|hasOne|belongsTo|belongsToMany)\\s*\\(\\s*([A-Za-z0-9_]+)`,
        "g",
      );
      let aMatch;
      while ((aMatch = assocRegex.exec(content)) !== null) {
        relationships.push({
          field: aMatch[2].toLowerCase(),
          targetTable: aMatch[2],
          type: aMatch[1] === "belongsTo" ? "belongsTo" : "hasMany",
        });
      }
      schemas.push({ database_type: "Sequelize (SQL)", table_name: tableName, fields, relationships });
    }
  }

  // 4. TypeORM (TypeScript / SQL)
  // Matches: @Entity() followed by export class User { ... @Column() field: type; ... }
  if (content.includes("@Entity")) {
    const typeOrmRegex = /@Entity\s*\([^)]*\)[\s\S]*?class\s+([A-Za-z0-9_]+)/g;
    let match;
    while ((match = typeOrmRegex.exec(content)) !== null) {
      const tableName = match[1];
      const fields = [];
      const relationships = [];
      const block = extractBlock(content, match.index + match[0].length - 1) || "";
      const memberRegex =
        /@(Column|PrimaryGeneratedColumn|PrimaryColumn|ManyToOne|OneToMany|OneToOne|ManyToMany)\s*(\((?:[^()]|\([^()]*\))*\))?\s*(?:public\s+|private\s+)?(\w+)\s*[?!]?\s*:\s*([A-Za-z0-9_<>\[\]]+)/g;
      let mMatch;
      while ((mMatch = memberRegex.exec(block)) !== null) {
        const [, decorator, decoratorArgs, fieldName, fieldType] = mMatch;
        const isRelation = /ManyToOne|OneToMany|OneToOne|ManyToMany/.test(decorator);
        fields.push({ name: fieldName, type: fieldType, isForeignKey: isRelation });
        if (isRelation) {
          // The target entity is usually the first arrow-function arg,
          // e.g. `@ManyToOne(() => User)` - fall back to the field's own
          // TS type if that arg can't be found.
          const targetMatch = decoratorArgs && decoratorArgs.match(/=>\s*([A-Za-z0-9_]+)/);
          relationships.push({
            field: fieldName,
            targetTable: (targetMatch && targetMatch[1]) || fieldType.replace(/\[\]$/, ""),
            type: decorator === "OneToMany" || decorator === "ManyToMany" ? "hasMany" : "belongsTo",
          });
        }
      }
      schemas.push({ database_type: "TypeORM (SQL)", table_name: tableName, fields, relationships });
    }
  }

  // 5. SQLAlchemy / Django (Python)
  // Matches: class User(models.Model): ... field = models.CharField(...) / Column(...)
  if (
    ext === ".py" &&
    (content.includes("models.Model") ||
      content.includes("Base") ||
      content.includes("db.Model"))
  ) {
    const pyRegex =
      /class\s+([A-Za-z0-9_]+)\s*\((?:models\.Model|Base|db\.Model|.*Base)\):/g;
    let match;
    while ((match = pyRegex.exec(content)) !== null) {
      const tableName = match[1];
      const fields = [];
      const relationships = [];

      // Grab the indented body following the class line, up to the next
      // line at column 0 (or a sibling top-level statement) - Python
      // bodies are whitespace-delimited, not brace-delimited.
      const bodyStart = match.index + match[0].length;
      const rest = content.slice(bodyStart);
      const bodyEndMatch = rest.match(/\n(?=\S)/);
      const body = bodyEndMatch ? rest.slice(0, bodyEndMatch.index) : rest;

      const fieldRegex =
        /^\s+(\w+)\s*=\s*(?:models\.|db\.Column\(|Column\()?([A-Za-z_]+)\(([^)\n]*)\)/gm;
      let fMatch;
      while ((fMatch = fieldRegex.exec(body)) !== null) {
        const [, fieldName, fieldType, args] = fMatch;
        const isForeignKey = /ForeignKey|OneToOne|ManyToMany|relationship/.test(fieldType);
        fields.push({ name: fieldName, type: fieldType, isForeignKey });
        if (isForeignKey) {
          const targetMatch = args.match(/['"]([A-Za-z0-9_.]+)['"]/);
          if (targetMatch) {
            relationships.push({
              field: fieldName,
              targetTable: targetMatch[1].split(".").pop(),
              type: fieldType === "ManyToMany" ? "hasMany" : "belongsTo",
            });
          }
        }
      }
      schemas.push({ database_type: "Python ORM", table_name: tableName, fields, relationships });
    }
  }

  // 6. Raw MongoDB driver usage (Python's PyMongo, Node's native `mongodb`
  // driver) - unlike every ORM/ODM above, there's no schema declaration at
  // all: just a client connection, a database handle taken off it, and
  // named collections taken off *that*, with plain dict/object literals
  // passed straight into insert_one/insert_many (Python) or
  // insertOne/insertMany (Node). Every uniquely-named collection found
  // this way is still a detected "table" - it just has no declared fields,
  // so fields[] is filled in on a best-effort basis by scanning this same
  // file's insert calls for literal dict/object keys instead, and stays
  // empty (never throws) if no insert calls reference the collection at
  // all - the same "degrade to a bare table name" behavior every pattern
  // above already relies on. relationships[] is always [] here since
  // PyMongo/the native driver have no ref/foreign-key concept to read.
  //
  // Table names already claimed by an actual Mongoose model declaration
  // (section 1, above) are skipped so the same model isn't double-counted
  // as both "Mongoose (NoSQL)" and a raw driver - e.g. a Mongoose Model
  // also exposes `.insertMany()`, and a codebase might additionally reach
  // into `mongoose.connection.db.collection('X')` for the same collection
  // `X` a Mongoose schema already declares. This only catches collisions
  // within the same file, since (like every detector in this file) this
  // function only ever sees one file at a time.
  const mongooseTableNames = new Set(
    schemas
      .filter((s) => s.database_type === "Mongoose (NoSQL)")
      .map((s) => s.table_name),
  );

  // 6a. Raw PyMongo (Python)
  // Matches: client = MongoClient(...) -> db = client['name'] ->
  // users = db['User'] / db.User, then best-effort scans for
  // users.insert_one({...}) / users.insert_many([{...}, ...]) - including
  // the un-assigned chained form, db['User'].insert_one({...}).
  if (ext === ".py" && content.includes("MongoClient")) {
    // a) Client handles: `client = MongoClient(...)` (optionally the
    // `pymongo.MongoClient(...)` spelling).
    const pyClientVars = new Set();
    const pyClientVarRegex = /(\w+)\s*=\s*(?:pymongo\.)?MongoClient\s*\(/g;
    let pyClientMatch;
    while ((pyClientMatch = pyClientVarRegex.exec(content)) !== null) {
      pyClientVars.add(pyClientMatch[1]);
    }

    // b) Database handles taken off a client var, e.g. `db = client['project']`
    // or `db = client.project` - this selects a *database*, not a
    // collection, so it's tracked separately and excluded from the
    // collection scan below (otherwise `project` would wrongly show up as
    // a "collection").
    const pyDbVars = new Set();
    for (const clientVar of pyClientVars) {
      const dbVarRegex = new RegExp(
        `(\\w+)\\s*=\\s*${escapeRegex(clientVar)}\\s*(?:\\[\\s*['"][^'"]+['"]\\s*\\]|\\.[A-Za-z_]\\w*(?!\\s*\\())`,
        "g",
      );
      let dbVarMatch;
      while ((dbVarMatch = dbVarRegex.exec(content)) !== null) {
        pyDbVars.add(dbVarMatch[1]);
      }
    }

    // c) Collections taken off a database handle - `users = db['User']` or
    // `users = db.User` - each uniquely-named one is a detected "table".
    // Maps tableName -> the set of variable names bound to it (may be
    // empty if the collection is only ever accessed via the chained form).
    const pyCollections = new Map();
    for (const dbVar of pyDbVars) {
      const collAssignRegex = new RegExp(
        `(\\w+)\\s*=\\s*${escapeRegex(dbVar)}\\s*(?:\\[\\s*['"]([^'"]+)['"]\\s*\\]|\\.([A-Za-z_]\\w*)(?!\\s*\\())`,
        "g",
      );
      let collMatch;
      while ((collMatch = collAssignRegex.exec(content)) !== null) {
        const varName = collMatch[1];
        const tableName = collMatch[2] || collMatch[3];
        if (!pyCollections.has(tableName)) pyCollections.set(tableName, new Set());
        pyCollections.get(tableName).add(varName);
      }

      // Un-assigned chained access, e.g. `db['User'].insert_one({...})`.
      const chainedRegex = new RegExp(
        `${escapeRegex(dbVar)}\\s*(?:\\[\\s*['"]([^'"]+)['"]\\s*\\]|\\.([A-Za-z_]\\w*))\\s*\\.\\s*insert_(?:one|many)\\s*\\(`,
        "g",
      );
      let chainedMatch;
      while ((chainedMatch = chainedRegex.exec(content)) !== null) {
        const tableName = chainedMatch[1] || chainedMatch[2];
        if (!pyCollections.has(tableName)) pyCollections.set(tableName, new Set());
      }
    }

    for (const [tableName, varNames] of pyCollections.entries()) {
      if (mongooseTableNames.has(tableName)) continue;

      const fields = [];
      const seenFields = new Set();
      const insertRegexes = [];
      for (const varName of varNames) {
        insertRegexes.push(
          new RegExp(`\\b${escapeRegex(varName)}\\s*\\.\\s*(insert_one|insert_many)\\s*\\(`, "g"),
        );
      }
      for (const dbVar of pyDbVars) {
        insertRegexes.push(
          new RegExp(
            `${escapeRegex(dbVar)}\\s*(?:\\[\\s*['"]${escapeRegex(tableName)}['"]\\s*\\]|\\.${escapeRegex(tableName)})\\s*\\.\\s*(insert_one|insert_many)\\s*\\(`,
            "g",
          ),
        );
      }

      for (const insertRegex of insertRegexes) {
        let insertMatch;
        while ((insertMatch = insertRegex.exec(content)) !== null) {
          const openParenIndex = insertRegex.lastIndex - 1;
          const argsText = extractCallArgs(content, openParenIndex);
          if (argsText) {
            for (const field of extractFieldsFromCallArgs(argsText)) {
              if (!seenFields.has(field.name)) {
                seenFields.add(field.name);
                fields.push(field);
              }
            }
          }
        }
      }

      schemas.push({
        database_type: "Raw PyMongo (MongoDB)",
        table_name: tableName,
        fields,
        relationships: [],
      });
    }
  }

  // 6b. Raw MongoDB driver (Node.js)
  // Matches: client = new MongoClient(...) -> db = client.db('name') ->
  // db.collection('User'), assigned to a variable or chained directly,
  // then best-effort scans for <var>.insertOne({...}) / .insertMany([...])
  // the same way the PyMongo block above does.
  const JS_EXTS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
  if (JS_EXTS.has(ext) && content.includes("MongoClient")) {
    const jsClientVars = new Set();
    const jsClientVarRegex = /(\w+)\s*=\s*new\s+MongoClient\s*\(/g;
    let jsClientMatch;
    while ((jsClientMatch = jsClientVarRegex.exec(content)) !== null) {
      jsClientVars.add(jsClientMatch[1]);
    }

    const jsDbVars = new Set();
    for (const clientVar of jsClientVars) {
      const dbVarRegex = new RegExp(
        `(\\w+)\\s*=\\s*${escapeRegex(clientVar)}\\s*\\.\\s*db\\s*\\(`,
        "g",
      );
      let dbVarMatch;
      while ((dbVarMatch = dbVarRegex.exec(content)) !== null) {
        jsDbVars.add(dbVarMatch[1]);
      }
    }

    const jsCollections = new Map();
    for (const dbVar of jsDbVars) {
      const collAssignRegex = new RegExp(
        `(\\w+)\\s*=\\s*${escapeRegex(dbVar)}\\s*\\.\\s*collection\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`,
        "g",
      );
      let collMatch;
      while ((collMatch = collAssignRegex.exec(content)) !== null) {
        const varName = collMatch[1];
        const tableName = collMatch[2];
        if (!jsCollections.has(tableName)) jsCollections.set(tableName, new Set());
        jsCollections.get(tableName).add(varName);
      }

      // Un-assigned chained access, e.g. `db.collection('User').insertOne({...})`.
      const chainedRegex = new RegExp(
        `${escapeRegex(dbVar)}\\s*\\.\\s*collection\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)\\s*\\.\\s*insert(?:One|Many)\\s*\\(`,
        "g",
      );
      let chainedMatch;
      while ((chainedMatch = chainedRegex.exec(content)) !== null) {
        const tableName = chainedMatch[1];
        if (!jsCollections.has(tableName)) jsCollections.set(tableName, new Set());
      }
    }

    for (const [tableName, varNames] of jsCollections.entries()) {
      if (mongooseTableNames.has(tableName)) continue;

      const fields = [];
      const seenFields = new Set();
      const insertRegexes = [];
      for (const varName of varNames) {
        insertRegexes.push(
          new RegExp(`\\b${escapeRegex(varName)}\\s*\\.\\s*(insertOne|insertMany)\\s*\\(`, "g"),
        );
      }
      for (const dbVar of jsDbVars) {
        insertRegexes.push(
          new RegExp(
            `${escapeRegex(dbVar)}\\s*\\.\\s*collection\\s*\\(\\s*['"]${escapeRegex(tableName)}['"]\\s*\\)\\s*\\.\\s*(insertOne|insertMany)\\s*\\(`,
            "g",
          ),
        );
      }

      for (const insertRegex of insertRegexes) {
        let insertMatch;
        while ((insertMatch = insertRegex.exec(content)) !== null) {
          const openParenIndex = insertRegex.lastIndex - 1;
          const argsText = extractCallArgs(content, openParenIndex);
          if (argsText) {
            for (const field of extractFieldsFromCallArgs(argsText)) {
              if (!seenFields.has(field.name)) {
                seenFields.add(field.name);
                fields.push(field);
              }
            }
          }
        }
      }

      schemas.push({
        database_type: "Raw MongoDB Driver (Node.js)",
        table_name: tableName,
        fields,
        relationships: [],
      });
    }
  }

  return schemas;
}

/**
 * Repo-wide post-processing step, called once with *every* detected table
 * across the whole scan (unlike extractDatabaseSchemas above, which only
 * ever sees one file at a time and can't see the other tables it would
 * need to compare against). Fills in relationships[] by naming heuristic
 * for tables that don't already have any - which in practice means the
 * schemaless raw-driver tables (section 6 above always leaves
 * relationships: []), plus any ORM model whose regex-based extraction
 * happened to miss a real relationship. A table that already has real,
 * parsed relationships (from an actual ORM's `ref`/`@ManyToOne`/
 * `ForeignKey`/etc.) is left alone - this only ever adds a best-effort
 * guess where there was nothing before, never overrides real data.
 *
 * Two heuristics, both flagged `inferred: true` so the frontend can draw
 * them differently (dashed, labelled "inferred") from a relationship an
 * ORM actually declared:
 *   1. A field named like `<entity>_id` / `<entity>Id` where `<entity>`
 *      (singular or plural) matches another table's name.
 *   2. A field name that exactly matches another table's own commonly-used
 *      identifying field (e.g. a `username` field showing up in some other
 *      collection, when a `User`/`Users` table already has a `username`
 *      field of its own) - this is the shape raw PyMongo code actually
 *      tends to take: no `_id` suffix at all, just the same natural key
 *      reused across collections.
 *
 * @param {Array} tables - every table detected across the whole repo.
 * @returns {Array} the same array, with relationships[] filled in where inferred.
 */
function inferCrossTableRelationships(tables) {
  if (!Array.isArray(tables) || tables.length === 0) return tables;

  const byLowerName = new Map();
  tables.forEach((t) => {
    const key = String(t.table_name || "").toLowerCase();
    if (key && !byLowerName.has(key)) byLowerName.set(key, t);
  });

  function findTableByEntityGuess(guess) {
    if (!guess) return null;
    const singular = guess.endsWith("s") ? guess.slice(0, -1) : guess;
    const plural = guess.endsWith("s") ? guess : `${guess}s`;
    return byLowerName.get(guess) || byLowerName.get(singular) || byLowerName.get(plural) || null;
  }

  // Which field names does each table already carry, for heuristic #2.
  const fieldOwners = new Map(); // fieldNameLower -> Set(tableName)
  tables.forEach((t) => {
    (t.fields || []).forEach((f) => {
      const key = String(f.name || "").toLowerCase();
      if (!key) return;
      if (!fieldOwners.has(key)) fieldOwners.set(key, new Set());
      fieldOwners.get(key).add(t.table_name);
    });
  });

  tables.forEach((t) => {
    if (t.relationships && t.relationships.length > 0) return; // real data wins - never override

    const inferred = [];
    const seenTargets = new Set();

    (t.fields || []).forEach((f) => {
      const fieldName = String(f.name || "");
      const fieldLower = fieldName.toLowerCase();

      // Heuristic 1: `<entity>_id` / `<entity>id` naming.
      const idMatch = fieldLower.match(/^(.+?)_?id$/);
      if (idMatch && idMatch[1] && idMatch[1] !== t.table_name.toLowerCase()) {
        const target = findTableByEntityGuess(idMatch[1]);
        if (target && target.table_name !== t.table_name && !seenTargets.has(target.table_name)) {
          seenTargets.add(target.table_name);
          inferred.push({ field: fieldName, targetTable: target.table_name, type: "belongsTo", inferred: true });
          f.isForeignKey = true;
          return;
        }
      }

      // Heuristic 2: shares a natural-key field name with another table
      // that ISN'T also this table (e.g. "username" showing up in both
      // "User" and some other collection that references a user by name
      // rather than by a generated id).
      const owners = fieldOwners.get(fieldLower);
      if (owners && owners.size > 1) {
        for (const ownerName of owners) {
          if (ownerName === t.table_name) continue;
          if (seenTargets.has(ownerName)) continue;
          // Prefer an owner whose table name itself resembles the field
          // name (e.g. field "username" -> table "User"/"Users") over an
          // arbitrary other table that merely happens to share a common
          // field like "status" or "description".
          const ownerLower = ownerName.toLowerCase();
          const fieldStem = fieldLower.replace(/name$/, "");
          if (ownerLower === fieldLower || ownerLower === fieldStem || `${ownerLower}s` === fieldLower || `${ownerLower}s` === fieldStem) {
            seenTargets.add(ownerName);
            inferred.push({ field: fieldName, targetTable: ownerName, type: "belongsTo", inferred: true });
            f.isForeignKey = true;
          }
        }
      }
    });

    if (inferred.length > 0) t.relationships = inferred;
  });

  return tables;
}

module.exports = extractDatabaseSchemas;
module.exports.inferCrossTableRelationships = inferCrossTableRelationships;
