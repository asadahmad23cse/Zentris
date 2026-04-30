import { logger } from "../utils/logger";
import { scanAndRedactSensitiveData } from "./dlpGuard";

export interface StreamingInspectionResult {
  safe: boolean;
  terminate: boolean;
  redactedChunk: string;
  detectedTypes: string[];
  reason?: string;
}

export class StreamingGuard {
  public inspect(chunk: string, accumulated: string): StreamingInspectionResult {
    const chunkResult = scanAndRedactSensitiveData(chunk);
    const rollingResult = scanAndRedactSensitiveData(`${accumulated}${chunk}`);

    if (chunkResult.detectedTypes.length > 0) {
      logger.warn({ detectedTypes: chunkResult.detectedTypes }, "stream_sensitive_pattern_redacted");
    }

    const crossChunkLeakDetected =
      chunkResult.detectedTypes.length === 0 && rollingResult.detectedTypes.length > 0;

    if (crossChunkLeakDetected) {
      logger.warn(
        { detectedTypes: rollingResult.detectedTypes },
        "stream_sensitive_pattern_cross_chunk_detected"
      );
      return {
        safe: false,
        terminate: true,
        redactedChunk: "",
        detectedTypes: rollingResult.detectedTypes,
        reason: "cross_chunk_sensitive_pattern"
      };
    }

    return {
      safe: true,
      terminate: false,
      redactedChunk: chunkResult.redacted,
      detectedTypes: chunkResult.detectedTypes
    };
  }
}
