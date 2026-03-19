/**
 * UPSS Validate Prompt Tool
 *
 * Exposes prompt validation as a tool that can be called by LLM agents
 * or via the /upss-check slash command.
 *
 * Runs all 6 security gates and returns detailed results.
 */

import {
  SecurityContext,
  createSixGatePipeline,
  executeSixGates,
  formatGateResult,
  type SixGateResult,
} from "@upss/core";
import { UPSSPluginConfig } from "../config/plugin.js";

/**
 * Issue detected during validation
 */
export interface ValidationIssue {
  gate: string;
  controlId: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
  recommendation?: string;
}

/**
 * Gate-by-gate result
 */
export interface GateResult {
  gate: string;
  controlId: string;
  passed: boolean;
  violations: string[];
}

/**
 * Tool input parameters
 */
export interface ValidatePromptInput {
  /** The prompt text to validate */
  prompt: string;
  /** User role for RBAC checks */
  role?: "admin" | "developer" | "user";
  /** Optional context information */
  context?: Record<string, unknown>;
  /** Prompt ID for checksum verification */
  promptId?: string;
}

/**
 * Tool output result
 */
export interface ValidatePromptOutput {
  /** Whether the prompt is allowed */
  allowed: boolean;
  /** Normalized risk score (0-1) */
  riskScore: number;
  /** List of issues detected */
  issues: ValidationIssue[];
  /** Gate-by-gate results */
  gates: GateResult[];
  /** Sanitized prompt if applicable */
  sanitizedPrompt?: string;
  /** Human-readable summary */
  summary: string;
  /** Formatted gate result for display */
  formatted: string;
}

/**
 * Create the UPSSValidatePrompt tool with full 6-gate pipeline
 */
export function createValidatePromptTool(config: Required<UPSSPluginConfig>) {
  // Create 6-gate pipeline
  const pipeline = createSixGatePipeline({
    maxUserPromptLength: config.maxUserPromptLength,
    maxSystemPromptLength: config.maxSystemPromptLength,
    rateLimitDbPath: config.rootDir + "/upss.db",
    failOnMissingChecksum: false, // Soft failure for manual checks
    enableRBAC: true,
    enableRateLimit: false, // Disable rate limiting for manual checks
    enableChecksum: config.enforceChecksums,
  });

  /**
   * Validate a prompt against all 6 UPSS security gates
   */
  async function validate(input: ValidatePromptInput): Promise<ValidatePromptOutput> {
    const context = new SecurityContext({
      userId: (input.context?.userId as string) ?? "anonymous",
      promptId: input.promptId ?? "validation",
      riskLevel: "medium",
      metadata: {
        role: input.role ?? "user",
        category: "user",
        ...input.context,
      },
    });

    // Execute all 6 gates
    const gateResult = await executeSixGates(pipeline, input.prompt, context);

    // Convert gate results to issues
    const issues: ValidationIssue[] = [];
    for (const [gateName, result] of Object.entries(gateResult.gateResults)) {
      if (result && !result.isSafe) {
        for (const violation of result.violations) {
          issues.push({
            gate: gateName,
            controlId: result.metadata.controlId as string ?? "UNKNOWN",
            category: "security",
            severity: determineSeverity(result.metadata.controlId as string),
            message: violation,
            recommendation: getRecommendation(result.metadata.controlId as string),
          });
        }
      }
    }

    // Build gate-by-gate results
    const gates: GateResult[] = [];
    for (const [gateName, result] of Object.entries(gateResult.gateResults)) {
      if (result) {
        gates.push({
          gate: gateName,
          controlId: result.metadata.controlId as string ?? "N/A",
          passed: result.isSafe,
          violations: [...result.violations],
        });
      }
    }

    const formatted = formatGateResult(gateResult);
    const allowed = gateResult.passed || config.defaultAction !== "block";
    const summary = gateResult.passed
      ? "🛡️ All 6 security gates passed"
      : `🚨 Security violation: ${gateResult.failedControlId} (${gateResult.failedGate})`;

    return {
      allowed,
      riskScore: gateResult.riskScore,
      issues,
      gates,
      sanitizedPrompt: gateResult.prompt !== input.prompt ? gateResult.prompt : undefined,
      summary,
      formatted,
    };
  }

  return {
    name: "upss_validate_prompt",
    description:
      "Validate a prompt against the Universal Prompt Security Standard (UPSS) 6-gate security chain. " +
      "Checks for injection patterns, encoding issues, length limits, RBAC, checksum integrity, and rate limits. " +
      "Use /upss-check <prompt> to manually audit any string.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: {
          type: "string",
          description: "The prompt text to validate",
        },
        role: {
          type: "string",
          enum: ["admin", "developer", "user"],
          description: "User role for RBAC checks (default: user)",
        },
        promptId: {
          type: "string",
          description: "Prompt ID for checksum verification (Gate 5)",
        },
        context: {
          type: "object",
          description: "Optional context information",
        },
      },
      required: ["prompt"],
    },
    execute: validate,
  };
}

/**
 * Determine severity based on control ID
 */
function determineSeverity(controlId: string): ValidationIssue["severity"] {
  if (controlId === "CR-03") return "critical"; // Checksum tampering
  if (controlId === "RS-01") return "critical"; // Injection
  if (controlId === "RS-02") return "high"; // Role confusion
  if (controlId === "RS-03") return "medium"; // Length
  if (controlId === "RS-04") return "high"; // Encoding exploit
  if (controlId === "RS-05") return "medium"; // Rate limit
  return "medium";
}

/**
 * Get recommendation based on control ID
 */
function getRecommendation(controlId: string): string {
  const recommendations: Record<string, string> = {
    "RS-01": "Remove instruction override patterns from the prompt",
    "RS-02": "Clarify role boundaries and remove confusion patterns",
    "RS-03": "Reduce prompt length to within limits",
    "RS-04": "Remove null bytes or control characters from input",
    "RS-05": "Wait before retrying - rate limit exceeded",
    "CR-03": "Prompt artifact may be tampered - verify checksum",
  };
  return recommendations[controlId] ?? "Review and address the security issue";
}