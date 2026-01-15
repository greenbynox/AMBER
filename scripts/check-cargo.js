const { spawnSync } = require("child_process");

const command = process.platform === "win32" ? "where" : "which";
const result = spawnSync(command, ["cargo"], { stdio: "ignore" });

if (result.status !== 0) {
  console.error("cargo introuvable. Installe Rust depuis https://rustup.rs puis réessaie.");
  process.exit(1);
}
