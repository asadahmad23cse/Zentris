import { InjectionDetector } from "./injectionDetector";
import { InputNormalizer } from "./inputNormalizer";

export interface RagChunkInput {
  content: string;
  source?: string;
}

export interface SanitizedRagChunk {
  content: string;
  source: string;
  trustLevel: "untrusted";
  chunkId: string;
}

export interface DroppedRagChunk {
  source: string;
  chunkId: string;
  reason: string;
}

export interface RagSanitizationResult {
  accepted: SanitizedRagChunk[];
  dropped: DroppedRagChunk[];
}

const INSTRUCTION_LIKE_PATTERNS: ReadonlyArray<RegExp> = [
  /\b(?:ignore|disregard|override|bypass)\b[\s\S]{0,40}\b(?:instructions?|rules?|policy)\b/i,
  /\b(?:you\s+are\s+now|act\s+as|from\s+now\s+on)\b/i,
  /\b(?:reveal|show|print|dump|expose)\b[\s\S]{0,30}\b(?:system\s+prompt|secrets?|credentials?)\b/i,
  /\b(?:do\s+not\s+follow|stop\s+following)\b[\s\S]{0,40}\b(?:system|developer|safety)\b/i,
  /\b(?:tool|function)\s+(?:call|invoke|execute)\b/i
];

const hasInstructionLikePattern = (text: string): boolean =>
  INSTRUCTION_LIKE_PATTERNS.some((pattern) => pattern.test(text));

const normalizeSource = (source: string | undefined, chunkIndex: number): string => {
  const cleaned = (source ?? "").trim();
  if (cleaned.length === 0) {
    return `rag_source_${chunkIndex + 1}`;
  }
  return cleaned.slice(0, 128);
};

export class RagSecurityGuard {
  private readonly injectionDetector = new InjectionDetector();
  private readonly inputNormalizer = new InputNormalizer();

  public async sanitizeChunks(chunks: RagChunkInput[]): Promise<RagSanitizationResult> {
    const accepted: SanitizedRagChunk[] = [];
    const dropped: DroppedRagChunk[] = [];

    for (let index = 0; index < chunks.length; index += 1) {
      const chunk = chunks[index];
      const chunkId = `rag-${index + 1}`;
      const source = normalizeSource(chunk.source, index);
      const rawContent = chunk.content.trim();

      if (rawContent.length === 0) {
        dropped.push({ source, chunkId, reason: "empty_chunk" });
        continue;
      }

      const normalizedContent = this.inputNormalizer.normalize(rawContent);
      const injectionResult = await this.injectionDetector.detect(normalizedContent, rawContent);
      const instructionLike = hasInstructionLikePattern(normalizedContent);

      if (instructionLike || injectionResult.action !== "allow" || injectionResult.risk !== "low") {
        const reason = instructionLike ? "instruction_like_pattern" : injectionResult.reason;
        dropped.push({ source, chunkId, reason });
        continue;
      }

      accepted.push({
        content: rawContent,
        source,
        trustLevel: "untrusted",
        chunkId
      });
    }

    return { accepted, dropped };
  }
}
