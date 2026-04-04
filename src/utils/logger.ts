import pino from "pino";
import { config } from "../config";

export const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: "zentris" },
  timestamp: pino.stdTimeFunctions.isoTime
});
