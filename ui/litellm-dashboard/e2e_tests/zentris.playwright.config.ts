import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/zentris",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: "list",
  outputDir: "../../test-results/zentris-dashboard",
  use: {
    baseURL: process.env.ZENTRIS_E2E_BASE_URL ?? "http://localhost",
    ...devices["Desktop Chrome"],
    acceptDownloads: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  timeout: 120_000,
  expect: { timeout: 15_000 },
});
