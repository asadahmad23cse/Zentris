const HTML_ENTITY_PATTERN = /&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g;
const HTML_ENTITY_MAP: Record<string, string> = {
  amp: "&",
  apos: "'",
  gt: ">",
  lt: "<",
  nbsp: " ",
  quot: "\""
};

const WHITESPACE_VARIANTS_PATTERN = /[\s\u00A0\u1680\u180E\u2000-\u200D\u2028\u2029\u202F\u205F\u3000\uFEFF]+/gu;
const BASE64_CANDIDATE_PATTERN = /(?<![A-Za-z0-9+/=])([A-Za-z0-9+/=]{9,})(?![A-Za-z0-9+/=])/g;
const HEX_SEQUENCE_PATTERN = /\b(?:0x[a-fA-F0-9]{7,}|[a-fA-F0-9]{7,})\b/g;
const SPLIT_JOIN_SEPARATOR = "[\\s\\p{P}\\u200B-\\u200D\\uFEFF_]*";

const SPLIT_TOKEN_TARGETS = [
  "system",
  "ignore",
  "prompt",
  "instructions",
  "execute",
  "admin",
  "password",
  "token"
] as const;

const SPLIT_TOKEN_PATTERNS = SPLIT_TOKEN_TARGETS.map((token) => ({
  pattern: new RegExp(
    `(?<![\\p{L}\\p{N}])${token.split("").join(SPLIT_JOIN_SEPARATOR)}(?![\\p{L}\\p{N}])`,
    "giu"
  ),
  token
}));

const decodeHtmlEntities = (value: string): string =>
  value.replace(HTML_ENTITY_PATTERN, (match, entity: string) => {
    const toCodePoint = (rawCodePoint: number): string => {
      if (!Number.isInteger(rawCodePoint) || rawCodePoint < 0 || rawCodePoint > 0x10ffff) {
        return match;
      }
      return String.fromCodePoint(rawCodePoint);
    };

    if (entity.startsWith("#x") || entity.startsWith("#X")) {
      const codePoint = Number.parseInt(entity.slice(2), 16);
      return Number.isFinite(codePoint) ? toCodePoint(codePoint) : match;
    }

    if (entity.startsWith("#")) {
      const codePoint = Number.parseInt(entity.slice(1), 10);
      return Number.isFinite(codePoint) ? toCodePoint(codePoint) : match;
    }

    const named = HTML_ENTITY_MAP[entity.toLowerCase()];
    return named ?? match;
  });

const isPrintableText = (value: string): boolean => {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) {
      return false;
    }

    if (codePoint === 9 || codePoint === 10 || codePoint === 13) {
      continue;
    }

    if (codePoint < 32 || codePoint === 127) {
      return false;
    }
  }

  return true;
};

const isBase64Candidate = (candidate: string): boolean => {
  if (candidate.length <= 8) {
    return false;
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(candidate)) {
    return false;
  }
  if (candidate.includes("=") && !/={0,2}$/.test(candidate)) {
    return false;
  }
  if (candidate.length % 4 !== 0) {
    return false;
  }
  if (/^[A-Za-z]+$/.test(candidate)) {
    return false;
  }
  if (candidate.length < 16 && !/[+/=]/.test(candidate) && !/\d/.test(candidate)) {
    return false;
  }
  if (/^[a-fA-F0-9]+$/.test(candidate)) {
    return false;
  }
  return true;
};

const decodeBase64Safely = (candidate: string): string => {
  try {
    const decodedBuffer = Buffer.from(candidate, "base64");
    if (decodedBuffer.length === 0) {
      return "[BASE64: ENCODED_BLOB]";
    }

    const canonicalCandidate = candidate.replace(/=+$/, "");
    const canonicalDecoded = decodedBuffer.toString("base64").replace(/=+$/, "");
    if (canonicalCandidate !== canonicalDecoded) {
      return "[BASE64: ENCODED_BLOB]";
    }

    const decoded = decodedBuffer.toString("utf8");
    if (decoded.includes("\uFFFD") || !isPrintableText(decoded)) {
      return "[BASE64: ENCODED_BLOB]";
    }

    const printableDecoded = decoded.replace(WHITESPACE_VARIANTS_PATTERN, " ").trim();
    return `[BASE64: ${printableDecoded}]`;
  } catch {
    return "[BASE64: ENCODED_BLOB]";
  }
};

export class InputNormalizer {
  public normalize(raw: string): string {
    const decodedEntities = decodeHtmlEntities(raw);
    const unicodeNormalized = decodedEntities.normalize("NFKC");
    const collapsedWhitespace = unicodeNormalized.replace(WHITESPACE_VARIANTS_PATTERN, " ").trim();

    let splitTokensJoined = collapsedWhitespace;
    for (const splitPattern of SPLIT_TOKEN_PATTERNS) {
      splitTokensJoined = splitTokensJoined.replace(splitPattern.pattern, splitPattern.token);
    }

    const withBase64Annotations = splitTokensJoined.replace(BASE64_CANDIDATE_PATTERN, (match) => {
      if (!isBase64Candidate(match)) {
        return match;
      }
      return decodeBase64Safely(match);
    });

    const withHexAnnotations = withBase64Annotations.replace(HEX_SEQUENCE_PATTERN, (match) => `[HEX: ${match}]`);

    return withHexAnnotations;
  }
}
