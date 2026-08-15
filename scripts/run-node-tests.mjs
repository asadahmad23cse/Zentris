import { readdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const testDir = join(process.cwd(), "src", "tests");
const testFiles = readdirSync(testDir)
  .filter((file) => file.endsWith(".test.ts"))
  .sort()
  .map((file) => join(testDir, file));

if (testFiles.length === 0) {
  console.error("No backend test files found in src/tests");
  process.exit(1);
}

const tsxCli = join(process.cwd(), "node_modules", "tsx", "dist", "cli.cjs");
const result = spawnSync(process.execPath, [tsxCli, "--test", "--test-concurrency=1", "--test-force-exit", ...testFiles], {
  stdio: "inherit",
  shell: false
});

if (result.error) {
  console.error(result.error.message);
}

process.exit(result.status ?? 1);
