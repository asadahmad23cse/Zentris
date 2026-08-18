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
const testEnvironment = {
  ...process.env,
  NODE_ENV: "test",
  ZENTRIS_STRICT_CONFIG: "false",
  ZENTRIS_DEMO_ENABLED: "false",
  ZENTRIS_TEST_TELEMETRY: "false",
  REDIS_URL: "redis://localhost:6379",
  LITELLM_BASE_URL: "http://localhost:4000/v1",
  LITELLM_API_KEY: "test-key-not-secret",
  LITELLM_MODEL: "test-model",
  JWT_SECRET: "test-jwt-secret-at-least-32-characters",
  CONFIRMATION_TOKEN_SECRET: "test-confirmation-secret-at-least-32",
  LOG_LEVEL: "error",
  PORT: "3100"
};
const result = spawnSync(process.execPath, [tsxCli, "--test", "--test-concurrency=1", "--test-force-exit", ...testFiles], {
  stdio: "inherit",
  shell: false,
  env: testEnvironment
});

if (result.error) {
  console.error(result.error.message);
}

process.exit(result.status ?? 1);
