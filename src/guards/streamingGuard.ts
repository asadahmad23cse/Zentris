import { logger } from "../utils/logger";
import { scanAndRedactSensitiveData } from "./dlpGuard";

export interface StreamingInspectionResult {
  safe: boolean;
  terminate: boolean;
  redactedChunks: string[];
  detectedTypes: string[];
  reason?: string;
}

export interface StreamingInspectionState {
  pendingRaw: string;
  suspiciousEvents: number;
  rollingWindowChars: number;
  suspiciousEventLimit: number;
}

const clamp = (value: number, min: number, max: number): number =>
  Math.max(min, Math.min(max, value));

export class StreamingGuard {
  private readonly rollingWindowChars: number;
  private readonly suspiciousEventLimit: number;

  constructor(rollingWindowChars = 256, suspiciousEventLimit = 3) {
    this.rollingWindowChars = clamp(rollingWindowChars, 128, 512);
    this.suspiciousEventLimit = Math.max(1, suspiciousEventLimit);
  }

  public createState(): StreamingInspectionState {
    return {
      pendingRaw: "",
      suspiciousEvents: 0,
      rollingWindowChars: this.rollingWindowChars,
      suspiciousEventLimit: this.suspiciousEventLimit
    };
  }

  public inspectChunk(chunk: string, state: StreamingInspectionState): StreamingInspectionResult {
    const chunkResult = scanAndRedactSensitiveData(chunk, "output");
    state.pendingRaw += chunk;

    const rollingWindow = state.pendingRaw.slice(-state.rollingWindowChars);
    const rollingResult = scanAndRedactSensitiveData(rollingWindow, "output");

    const crossChunkLeakDetected =
      chunkResult.detectedTypes.length === 0 && rollingResult.detectedTypes.length > 0;

    const suspiciousTypes = new Set<string>(chunkResult.detectedTypes);
    if (crossChunkLeakDetected) {
      for (const type of rollingResult.detectedTypes) {
        suspiciousTypes.add(type);
      }
    }

    if (suspiciousTypes.size > 0) {
      state.suspiciousEvents += suspiciousTypes.size;
      logger.warn(
        { detectedTypes: Array.from(suspiciousTypes), suspiciousEvents: state.suspiciousEvents },
        "stream_sensitive_pattern_detected"
      );
    }

    const redactedChunks: string[] = [];
    const rawEmitLength = Math.max(0, state.pendingRaw.length - state.rollingWindowChars);
    if (rawEmitLength > 0) {
      const rawToEmit = state.pendingRaw.slice(0, rawEmitLength);
      state.pendingRaw = state.pendingRaw.slice(rawEmitLength);
      const redactedToEmit = scanAndRedactSensitiveData(rawToEmit, "output").redacted;
      if (redactedToEmit.length > 0) {
        redactedChunks.push(redactedToEmit);
      }
    }

    return {
      safe: suspiciousTypes.size === 0,
      terminate: false,
      redactedChunks,
      detectedTypes: Array.from(suspiciousTypes),
      ...(crossChunkLeakDetected ? { reason: "cross_chunk_sensitive_pattern_redacted" } : {})
    };
  }

  public flush(state: StreamingInspectionState): StreamingInspectionResult {
    if (state.pendingRaw.length === 0) {
      return {
        safe: true,
        terminate: false,
        redactedChunks: [],
        detectedTypes: []
      };
    }

    const redacted = scanAndRedactSensitiveData(state.pendingRaw, "output");
    state.pendingRaw = "";

    return {
      safe: true,
      terminate: false,
      redactedChunks: redacted.redacted.length > 0 ? [redacted.redacted] : [],
      detectedTypes: redacted.detectedTypes
    };
  }
}
