export type UserRole = "admin" | "operator" | "viewer" | "anonymous";

export type IntentType = "read" | "write" | "delete" | "execute" | "unknown";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp: number;
}

export interface ZentrisRequest {
  sessionId: string;
  userId: string;
  userRole: UserRole;
  rawInput: string;
  messages: ChatMessage[];
}

export interface GuardResult {
  safe: boolean;
  risk: "low" | "medium" | "high";
  reason: string;
  action: "allow" | "block" | "sanitize" | "require_confirmation";
}

export interface IntentClassificationResult {
  intent: IntentType;
  confidence: number;
  riskScore: number;
}

export interface AuthorizationResult {
  authorized: boolean;
  reason: string;
}

export type ContextGuardResult = GuardResult & { riskScore: number };

export interface PipelineContext {
  request: ZentrisRequest;
  guardResults: GuardResult[];
  normalizedInput: string;
  sanitizedInput: string;
  injectionResult?: GuardResult;
  contextResult?: ContextGuardResult;
  intentResult?: IntentClassificationResult;
  authResult?: AuthorizationResult;
  piiDetected?: string[];
}

export interface AuditLogEntry {
  timestamp: number;
  sessionId: string;
  userId: string;
  input: string;
  normalizedInput: string;
  decisions: GuardResult[];
  finalAction: GuardResult["action"];
  riskScore: number;
  durationMs: number;
  userRole: UserRole;
  intent: IntentType;
}
