/**
 * message:preprocessed hook implementation
 *
 * Intercepts the fully enriched user message and passes it through
 * the UPSS 6-gate validation pipeline.
 *
 * Gates executed (halt on first failure):
 * 1. RS-04: Encoding validation
 * 2. RS-03: Length validation
 * 3. RS-01/RS-02: Forbidden pattern detection
 * 4. RS-02: Structural role separation (RBAC)
 * 5. CR-03: Checksum integrity (if prompt artifact)
 * 6. RS-05: Rate limiting
 */

import {
  SecurityContext,
  createSixGatePipeline,
  executeSixGates,
  formatGateResult,
  type SixGateResult,
} from "@upss/core";
import { UPSSPluginConfig } from "../config/plugin.js";
import { HookValidationResult, MessagePreprocessedPayload } from "./types.js";

/**
 * Create message:preprocessed hook handler with full 6-gate pipeline
 */
export function createMessagePreprocessedHook(config: Required<UPSSPluginConfig>) {
  // Create 6-gate pipeline with configuration
  const pipeline = createSixGatePipeline({
    maxUserPromptLength: config.maxUserPromptLength,
    maxSystemPromptLength: config.maxSystemPromptLength,
    rateLimitDbPath: config.rootDir + "/upss.db",
    failOnMissingChecksum: false, // Soft failure for user prompts
    enableRBAC: true,
    enableRateLimit: config.enableAuditLogging, // Use same flag for rate limit
    enableChecksum: config.enforceChecksums,
  });

  return async (payload: MessagePreprocessedPayload): Promise<HookValidationResult> => {
    const context = new SecurityContext({
      userId: payload.userId,
      promptId: payload.metadata?.promptId as string ?? "user-message",
      riskLevel: (payload.metadata?.riskLevel as "low" | "medium" | "high") ?? "medium",
      metadata: {
        ...payload.metadata,
        role: (payload.metadata?.role as string) ?? "user",
        category: "user",
      },
    });

    // Execute all 6 gates
    const gateResult = await executeSixGates(pipeline, payload.message, context);

    // Determine action based on result and config
    const action = determineAction(gateResult, config);

    // Log if audit enabled
    if (config.enableAuditLogging) {
      logSecurityEvent(gateResult, payload.userId, "message:preprocessed");
    }

    return {
      allowed: gateResult.passed || config.defaultAction !== "block",
      riskScore: gateResult.riskScore,
      violations: gateResult.violations,
      sanitizedPrompt: gateResult.prompt !== payload.message ? gateResult.prompt : undefined,
      action,
      gateResult: {
        passed: gateResult.passed,
        failedGate: gateResult.failedGate,
        failedControlId: gateResult.failedControlId,
        formatted: formatGateResult(gateResult),
      },
    };
  };
}

/**
 * Determine the action to take based on validation result
 */
function determineAction(
  result: SixGateResult,
  config: Required<UPSSPluginConfig>
): "block" | "sanitize" | "warn" | "pass" {
  if (!result.passed) {
    if (config.defaultAction === "block") {
      return result.riskScore >= config.riskThreshold ? "block" : "warn";
    }
    if (config.defaultAction === "sanitize") {
      return "sanitize";
    }
    return "warn";
  }
  return "pass";
}

/**
 * Log security event for audit trail
 */
function logSecurityEvent(
  result: SixGateResult,
  userId: string,
  hook: string
): void {
  const event = {
    timestamp: new Date().toISOString(),
    hook,
    userId,
    passed: result.passed,
    riskScore: result.riskScore,
    failedGate: result.failedGate,
    failedControlId: result.failedControlId,
    violations: result.violations,
  };

  // Console output for now (will be replaced with SQLite logging)
  if (!result.passed) {
    console.error("[UPSS SECURITY]", formatGateResult(result));
  } else {
    console.log("[UPSS]", formatGateResult(result));
  }
}