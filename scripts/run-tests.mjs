import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { join } from "node:path";

const testDirectory = join(process.cwd(), "src", "tests");
const testFiles = readdirSync(testDirectory)
  .filter((name) => name.endsWith(".test.ts"))
  .sort()
  .map((name) => join(testDirectory, name));

if (testFiles.length === 0) {
  throw new Error("No TypeScript test files were found in src/tests.");
}

const testEnvironment = {
  ...process.env,
  NODE_ENV: "test",
  ZENTRIS_STRICT_CONFIG: "false",
  REDIS_URL: "redis://localhost:6379",
  LITELLM_BASE_URL: "http://localhost:4000",
  LITELLM_API_KEY: "sk-zentris-test-key-1234567890",
  JWT_SECRET: "zentris-test-jwt-secret-1234567890",
  CONFIRMATION_TOKEN_SECRET: "zentris-test-confirmation-secret-1234567890",
  LOG_LEVEL: "error",
  PORT: "3100"
};

const require = createRequire(import.meta.url);
const tsxCli = require.resolve("tsx/cli");
const result = spawnSync(process.execPath, [tsxCli, "--test", "--test-concurrency=1", "--test-force-exit", ...testFiles], {
  env: testEnvironment,
  stdio: "inherit"
});

process.exit(result.status ?? 1);
