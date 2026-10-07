const bcrypt = require("bcryptjs");
const db = require("./queries");

async function main() {
  await db.connect();

  const email = "demo@codeatlas.dev";
  const password = "password123";

  if (await db.findUserByEmail(email)) {
    console.log(`Demo user already exists: ${email}`);
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  await db.createUser({ email, passwordHash, username: "demo" });

  console.log("✅ Seeded demo user:");
  console.log(`   email:    ${email}`);
  console.log(`   password: ${password}`);
}

main()
  .catch((error) => {
    console.error("❌ Seed failed:", error.message);
    process.exitCode = 1;
  })
  .finally(() => db.close());
