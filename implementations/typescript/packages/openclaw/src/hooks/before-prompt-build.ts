/**
 * before_prompt_build hook implementation
 *
 * Validates the final prompt that will be sent to the model using
 * the full 6-gate security pipeline.
 *
 * This is the most critical gate - it validates the complete prompt
 * including system prompts, tool outputs, and user input combined.
 *
 * Gates executed (halt on first failure):
 * 1. RS-04: Encoding validation
 * 2. RS-03: Length validation
 * 3. RS-01/RS-02: Forbidden pattern detection
 * 4. RS-02: Structural role separation (RBAC)
 * 5. CR-03: Checksum integrity (for prompt artifacts)
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
import { HookValidationResult, BeforePromptBuildPayload } from "./types.js";

/**
 * Create before_prompt_build hook handler with full 6-gate pipeline
 */
export function createBeforePromptBuildHook(config: Required<UPSSPluginConfig>) {
  // Create 6-gate pipeline with checksum verification enabled
  const pipeline = createSixGatePipeline({
    maxUserPromptLength: config.maxUserPromptLength,
    maxSystemPromptLength: config.maxSystemPromptLength,
    rateLimitDbPath: config.rootDir + "/upss.db",
    failOnMissingChecksum: config.enforceChecksums,
    enableRBAC: true,
    enableRateLimit: config.enableAuditLogging,
    enableChecksum: config.enforceChecksums,
  });

  return async (payload: BeforePromptBuildPayload): Promise<HookValidationResult> => {
    // Combine all prompt parts
    const combinedPrompt = [
      ...payload.systemPrompts,
      ...payload.toolPrompts,
      payload.userInput,
    ].join("\n\n");

    const context = new SecurityContext({
      userId: payload.userId,
      promptId: payload.promptRef ?? "final-prompt",
      riskLevel: "medium",
      metadata: {
        role: payload.metadata?.role ?? "user",
        category: payload.metadata?.category ?? "user",
        promptRef: payload.promptRef,
      },
    });

    // Execute all 6 gates
    const gateResult = await executeSixGates(pipeline, combinedPrompt, context);

    // Determine action based on result and config
    const action = determineAction(gateResult, config);

    // Log if audit enabled
    if (config.enableAuditLogging) {
      logSecurityEvent(gateResult, payload.userId, "before_prompt_build");
    }

    return {
      allowed: gateResult.passed || config.defaultAction !== "block",
      riskScore: gateResult.riskScore,
      violations: gateResult.violations,
      sanitizedPrompt: gateResult.prompt,
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
    // CR-03 (checksum) failures always block
    if (result.failedControlId === "CR-03") {
      return "block";
    }

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