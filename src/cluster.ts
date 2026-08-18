import cluster from "node:cluster";
import { availableParallelism } from "node:os";
import { start } from "./server";

const requested = Number.parseInt(process.env.WEB_CONCURRENCY ?? "", 10);
const workerCount = Number.isInteger(requested) && requested > 0
  ? Math.min(requested, 32)
  : Math.min(4, availableParallelism());

if (cluster.isPrimary && workerCount > 1) {
  let shuttingDown = false;
  const fork = (): void => {
    cluster.fork({ ...process.env, ZENTRIS_WORKER_COUNT: String(workerCount) });
  };
  for (let index = 0; index < workerCount; index += 1) fork();

  cluster.on("exit", () => {
    if (!shuttingDown) fork();
  });

  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    for (const worker of Object.values(cluster.workers ?? {})) worker?.process.kill(signal);
    const forcedExit = setTimeout(() => process.exit(1), 15_000);
    forcedExit.unref();
    cluster.disconnect(() => process.exit(0));
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
} else {
  void start().catch(() => process.exit(1));
}
