export type UserRole = "admin" | "operator" | "viewer" | "anonymous";

export type IntentType = "read" | "write" | "delete" | "execute" | "unknown";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
  timestamp: number;
}

export type SecurityRisk = "none" | "low" | "medium" | "high";
export type SecurityFindingKind = "prompt_injection" | "secret" | "pii";
export type SecurityFindingStage = "input" | "history" | "rag" | "output";
export type SecurityFindingAction = "allow" | "warn" | "redact";

export interface SecurityFinding {
  kind: SecurityFindingKind;
  ruleId: string;
  category: string;
  stage: SecurityFindingStage;
  risk: Exclude<SecurityRisk, "none">;
  score: number;
  action: SecurityFindingAction;
  start?: number;
  end?: number;
}

export interface SecurityMetadata {
  requestId: string;
  injectionDetected: boolean;
  warningApplied: boolean;
  dlpDetected: boolean;
  risk: SecurityRisk;
  score: number;
  matchedRules: string[];
  findings: SecurityFinding[];
}

export interface GenerationOptions {
  model?: string;
  streamOptions?: { includeUsage?: boolean };
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  stop?: string | string[];
  tools?: unknown[];
  toolChoice?: unknown;
  responseFormat?: unknown;
  apiKey?: string;
}

export interface AuthenticatedIdentity {
  userId: string;
  userRole: UserRole;
  tenantId: string | null;
  orgId: string | null;
}

export interface ToolInvocation {
  toolName: string;
  arguments: Record<string, unknown>;
  resourceScope: Record<string, unknown>;
  confirmationToken?: string;
}

export interface ZentrisRequest {
  sessionId: string;
  persistContext?: boolean;
  identity: AuthenticatedIdentity;
  rawInput: string;
  messages: ChatMessage[];
  toolInvocation?: ToolInvocation;
  generation?: GenerationOptions;
  requestId?: string;
}

export interface GuardResult {
  safe: boolean;
  risk: "low" | "medium" | "high";
  reason: string;
  action: "allow" | "block" | "sanitize" | "require_confirmation";
}

export interface InjectionDetectionResult extends GuardResult {
  detected: boolean;
  score: number;
  matchedRules: string[];
  findings: SecurityFinding[];
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
  contentLength: number;
  decisions: GuardResult[];
  finalAction: GuardResult["action"];
  riskScore: number;
  durationMs: number;
  userRole: UserRole;
  intent: IntentType;
}
