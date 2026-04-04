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

export interface PipelineContext {
  request: ZentrisRequest;
  guardResults: GuardResult[];
  normalizedInput: string;
  sanitizedInput: string;
}

export interface AuditLogEntry {
  timestamp: number;
  sessionId: string;
  userId: string;
  input: string;
  decisions: GuardResult[];
  finalAction: GuardResult["action"];
  riskScore: number;
  durationMs: number;
  userRole: UserRole;
  intent: IntentType;
}
