/**
 * OpenClaw Plugin Configuration Schema
 * 
 * Defines the configuration for the UPSS plugin.
 */

import { z } from "zod";

export const UPSSConfigSchema = z.object({
  rootDir: z.string().default("~/.openclaw/upss"),
  promptsConfigPath: z.string().default("prompts.json"),
  enforceChecksums: z.boolean().default(true),
  requireApproval: z.boolean().default(false),
  strictMode: z.boolean().default(false),
  defaultAction: z.enum(["block", "sanitize", "warn_only"]).default("block"),
  riskThreshold: z.number().min(0).max(1).default(0.7),
});

export type UPSSConfig = z.infer<typeof UPSSConfigSchema>;

/**
 * Default UPSS configuration.
 */
export const DEFAULT_UPSS_CONFIG: UPSSConfig = {
  rootDir: "~/.openclaw/upss",
  promptsConfigPath: "prompts.json",
  enforceChecksums: true,
  requireApproval: false,
  strictMode: false,
  defaultAction: "block",
  riskThreshold: 0.7,
};

/**
 * Validate prompt tool input.
 */
export const ValidatePromptInputSchema = z.object({
  prompt: z.string(),
  role: z.enum(["user", "system", "developer"]).optional(),
  context: z.record(z.unknown()).optional(),
});

export type ValidatePromptInput = z.infer<typeof ValidatePromptInputSchema>;

/**
 * Validate prompt tool output.
 */
export const ValidatePromptOutputSchema = z.object({
  allowed: z.boolean(),
  riskScore: z.number().min(0).max(1),
  issues: z.array(z.object({
    category: z.string(),
    severity: z.enum(["high", "medium", "low"]),
    span: z.object({
      start: z.number(),
      end: z.number(),
    }),
    recommendation: z.string(),
  })),
  sanitizedPrompt: z.string().optional(),
});

export type ValidatePromptOutput = z.infer<typeof ValidatePromptOutputSchema>;
