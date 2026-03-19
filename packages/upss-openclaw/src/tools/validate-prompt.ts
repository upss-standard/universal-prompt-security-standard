/**
 * UPSS Validate Prompt Tool.
 * 
 * Validates a prompt against UPSS security rules.
 */

import { SecurityPipeline } from "@upss/core";
import { BasicSanitizer } from "@upss/core";
import { InputValidator } from "@upss/core";
import { SimpleRBAC, Role } from "@upss/core";
import { SecurityContext, RiskLevel } from "@upss/core";
import {
  ValidatePromptInput,
  ValidatePromptOutput,
} from "../config/schema.js";

/**
 * Validate a prompt against UPSS security rules.
 * 
 * @param input - The validation input
 * @returns Validation result with allowed flag, risk score, and issues
 */
export async function validatePrompt(
  input: ValidatePromptInput
): Promise<ValidatePromptOutput> {
  const { prompt, role = "user", context = {} } = input;

  const pipeline = new SecurityPipeline()
    .use(new InputValidator())
    .use(new BasicSanitizer())
    .use(new SimpleRBAC());

  const contextObj = new SecurityContext({
    userId: context.userId as string || "cli-user",
    promptId: context.promptId as string || "validation",
    riskLevel: (context.riskLevel as RiskLevel) || "medium",
    metadata: {
      role: role as Role,
      category: context.category as string || "user",
      ...context,
    },
  });

  const result = await pipeline.execute(prompt, contextObj);

  return {
    allowed: result.allowed,
    riskScore: result.riskScore,
    issues: result.issues,
    sanitizedPrompt: result.issues.length > 0 ? result.prompt : undefined,
  };
}
