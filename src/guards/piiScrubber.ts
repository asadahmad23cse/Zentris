import { logger } from "../utils/logger";
import { scanAndRedactSensitiveData } from "./dlpGuard";

export class PiiScrubber {
  public scrub(text: string): { scrubbed: string; detectedTypes: string[] } {
    const result = scanAndRedactSensitiveData(text);
    for (const detectedType of result.detectedTypes) {
      logger.info({ detectedType }, "pii_detected");
    }
    return {
      scrubbed: result.redacted,
      detectedTypes: result.detectedTypes
    };
  }
}
