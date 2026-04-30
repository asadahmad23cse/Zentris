import toolPolicyJson from "../config/toolPolicy.json";
import { type ToolInvocation, type UserRole } from "../types";

type PrimitiveType = "string" | "number" | "boolean";
type ToolRisk = "low" | "medium" | "high";

interface FieldRule {
  type: PrimitiveType;
  pattern?: string;
  enum?: string[];
  min?: number;
  max?: number;
  minLength?: number;
  maxLength?: number;
}

interface SchemaRule {
  required: string[];
  properties: Record<string, FieldRule>;
}

interface ToolPolicyEntry {
  name: string;
  risk: ToolRisk;
  allowedRoles: UserRole[];
  arguments: SchemaRule;
  resourceScope: SchemaRule;
}

interface ToolPolicyDocument {
  version: string;
  defaultAction: "deny";
  tools: ToolPolicyEntry[];
}

export interface ToolPolicyValidationResult {
  allowed: boolean;
  reason: string;
  risk: ToolRisk;
  tool?: ToolPolicyEntry;
}

const policy = toolPolicyJson as unknown as ToolPolicyDocument;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === "object" && !Array.isArray(value));

const isToolRisk = (value: string): value is ToolRisk =>
  value === "low" || value === "medium" || value === "high";

const validateField = (value: unknown, rule: FieldRule): string | null => {
  if (rule.type === "string") {
    if (typeof value !== "string") {
      return "type_mismatch";
    }
    if (typeof rule.minLength === "number" && value.length < rule.minLength) {
      return "min_length_violation";
    }
    if (typeof rule.maxLength === "number" && value.length > rule.maxLength) {
      return "max_length_violation";
    }
    if (rule.enum && !rule.enum.includes(value)) {
      return "enum_violation";
    }
    if (rule.pattern && !new RegExp(rule.pattern).test(value)) {
      return "pattern_violation";
    }
    return null;
  }

  if (rule.type === "number") {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return "type_mismatch";
    }
    if (typeof rule.min === "number" && value < rule.min) {
      return "min_violation";
    }
    if (typeof rule.max === "number" && value > rule.max) {
      return "max_violation";
    }
    return null;
  }

  if (rule.type === "boolean") {
    if (typeof value !== "boolean") {
      return "type_mismatch";
    }
    return null;
  }

  return "unsupported_rule";
};

const validateAgainstSchema = (
  entityName: "arguments" | "resource_scope",
  input: unknown,
  schema: SchemaRule
): string | null => {
  if (!isRecord(input)) {
    return `${entityName}_invalid`;
  }

  for (const requiredField of schema.required) {
    if (!(requiredField in input)) {
      return `${entityName}_missing_required_${requiredField}`;
    }
  }

  const allowedFields = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(input)) {
    if (!allowedFields.has(key)) {
      return `${entityName}_not_allowlisted_${key}`;
    }
  }

  for (const [key, value] of Object.entries(input)) {
    const rule = schema.properties[key];
    if (!rule) {
      return `${entityName}_not_allowlisted_${key}`;
    }

    const validationError = validateField(value, rule);
    if (validationError) {
      return `${entityName}_invalid_${key}_${validationError}`;
    }
  }

  return null;
};

export class ToolRegistry {
  private readonly toolsByName = new Map<string, ToolPolicyEntry>();

  constructor() {
    for (const tool of policy.tools) {
      if (!tool.name || !isToolRisk(tool.risk)) {
        continue;
      }
      this.toolsByName.set(tool.name, tool);
    }
  }

  public validate(toolInvocation: ToolInvocation, userRole: UserRole): ToolPolicyValidationResult {
    if (!toolInvocation || typeof toolInvocation.toolName !== "string" || toolInvocation.toolName.trim().length === 0) {
      return {
        allowed: false,
        risk: "high",
        reason: "ambiguous_tool_call_missing_name"
      };
    }

    const tool = this.toolsByName.get(toolInvocation.toolName);
    if (!tool) {
      return {
        allowed: false,
        risk: "high",
        reason: `unknown_tool_name:${toolInvocation.toolName}`
      };
    }

    if (!tool.allowedRoles.includes(userRole)) {
      return {
        allowed: false,
        risk: tool.risk,
        reason: `tool_role_forbidden:${toolInvocation.toolName}`
      };
    }

    const argumentsValidation = validateAgainstSchema("arguments", toolInvocation.arguments, tool.arguments);
    if (argumentsValidation) {
      return {
        allowed: false,
        risk: tool.risk,
        reason: `${toolInvocation.toolName}:${argumentsValidation}`
      };
    }

    const scopeValidation = validateAgainstSchema("resource_scope", toolInvocation.resourceScope, tool.resourceScope);
    if (scopeValidation) {
      return {
        allowed: false,
        risk: tool.risk,
        reason: `${toolInvocation.toolName}:${scopeValidation}`
      };
    }

    return {
      allowed: true,
      risk: tool.risk,
      reason: "tool_policy_allow",
      tool
    };
  }
}
