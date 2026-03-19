/**
 * Hook handler for before_prompt_build.
 * 
 * Validates final prompt and determines action: block/sanitize/warn.
 */

import { SecurityPipeline } from "@upss/core";
import { BasicSanitizer } from "@upss/core";
import { InputValidator } from "@upss/core";
import { SecurityContext, RiskLevel } from "@upss/core";
import { UPSSConfig } from "../config/schema.js";

export interface BeforePromptBuildEvent {
  prompt: {
    systemPrompt: string;
    userInput: string;
    template?: string;
  };
  context: {
    userId: string;
    promptId: string;
    metadata?: Record<string, unknown>;
  };
}

export interface BeforePromptBuildResult {
  action: "block" | "sanitize" | "pass";
  sanitizedPrompt?: string;
  riskScore: number;
  issues: Array<{
    category: string;
    severity: "high" | "medium" | "low";
    span: { start: number; end: number };
    recommendation: string;
  }>;
}

/**
 * Handle before_prompt_build hook.
 * 
 * Validates the final prompt before it's sent to the LLM.
 */
export async function handleBeforePromptBuild(
  event: BeforePromptBuildEvent,
  config: UPSSConfig
): Promise<BeforePromptBuildResult> {
  const { prompt, context: ctx } = event;
  const { systemPrompt, userInput } = prompt;

  // Combine system prompt and user input for validation
  const fullPrompt = `${systemPrompt}\n\n${userInput}`;

  const pipeline = new SecurityPipeline()
    .use(new InputValidator())
    .use(new BasicSanitizer());

  const context = new SecurityContext({
    userId: ctx.userId,
    promptId: ctx.promptId,
    riskLevel: (ctx.metadata?.riskLevel as RiskLevel) || "medium",
    metadata: ctx.metadata || {},
  });

  const result = await pipeline.execute(fullPrompt, context);

  // Determine action based on config
  let action: "block" | "sanitize" | "pass" = "pass";

  if (!result.allowed) {
    // Map warn_only to pass
    action = config.defaultAction === "warn_only" ? "pass" : config.defaultAction;
  } else if (result.riskScore > config.riskThreshold) {
    // Risk threshold exceeded
    if (config.defaultAction === "block") {
      action = "block";
    } else if (config.defaultAction === "sanitize") {
      action = "sanitize";
    } else if (config.defaultAction === "warn_only") {
      action = "pass"; // Warn only - let it pass but the caller can check issues
    }
  }

  return {
    action,
    sanitizedPrompt: action === "sanitize" ? result.prompt : undefined,
    riskScore: result.riskScore,
    issues: result.issues,
  };
}
