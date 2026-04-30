import pino from "pino";
import { config } from "../config";
import { sanitizeForLogging, scanAndRedactSensitiveData } from "../guards/dlpGuard";

const sanitizeLogArgument = (value: unknown): unknown => {
  if (typeof value === "string") {
    return scanAndRedactSensitiveData(value).redacted;
  }
  return sanitizeForLogging(value);
};

export const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: "zentris" },
  timestamp: pino.stdTimeFunctions.isoTime,
  hooks: {
    logMethod(args, method) {
      const sanitizedArgs = args.map((arg) => sanitizeLogArgument(arg));
      (method as (...methodArgs: unknown[]) => void).apply(this, sanitizedArgs);
    }
  }
});
