/**
 * Hook handler for message:received.
 * 
 * Validates enriched user message and computes risk score.
 */

import { SecurityPipeline } from "@upss/core";
import { BasicSanitizer } from "@upss/core";
import { InputValidator } from "@upss/core";
import { SecurityContext, RiskLevel } from "@upss/core";
import { UPSSConfig } from "../config/schema.js";

export interface MessageReceivedEvent {
  message: {
    content: string;
    userId: string;
    metadata?: Record<string, unknown>;
  };
}

export interface MessageReceivedResult {
  allowed: boolean;
  riskScore: number;
  issues: Array<{
    category: string;
    severity: "high" | "medium" | "low";
    span: { start: number; end: number };
    recommendation: string;
  }>;
  sanitizedContent?: string;
}

/**
 * Handle message:received hook.
 * 
 * Validates the incoming user message for injection patterns and computes risk score.
 */
export async function handleMessageReceived(
  event: MessageReceivedEvent,
  config: UPSSConfig
): Promise<MessageReceivedResult> {
  const { message } = event;
  const { content, userId, metadata } = message;

  const pipeline = new SecurityPipeline()
    .use(new InputValidator())
    .use(new BasicSanitizer());

  const context = new SecurityContext({
    userId,
    promptId: metadata?.promptId as string || "message",
    riskLevel: (metadata?.riskLevel as RiskLevel) || "medium",
    metadata: {
      ...metadata,
      role: metadata?.role || "user",
    },
  });

  const result = await pipeline.execute(content, context);

  // Determine if action is needed based on config
  const shouldBlock = !result.allowed || result.riskScore > config.riskThreshold;
  const shouldSanitize = config.defaultAction === "sanitize" && result.issues.length > 0;

  return {
    allowed: shouldBlock ? false : true,
    riskScore: result.riskScore,
    issues: result.issues,
    sanitizedContent: shouldSanitize ? result.prompt : undefined,
  };
}
