/**
 * OpenClaw hook types for UPSS plugin.
 * 
 * These types define the hook interfaces that the UPSS plugin implements.
 * The actual hook system is provided by @openclaw/sdk.
 */

import { SecurityResult } from "@upss/core";

/**
 * Message before preprocessing
 */
export interface MessagePreprocessedPayload {
  userId: string;
  message: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Payload before prompt building
 */
export interface BeforePromptBuildPayload {
  userId: string;
  systemPrompts: string[];
  toolPrompts: string[];
  userInput: string;
  promptRef?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Agent end payload
 */
export interface AgentEndPayload {
  userId: string;
  promptIds: string[];
  riskScores: number[];
  sanitized: boolean;
  blocked: boolean;
  durationMs: number;
  metadata?: Record<string, unknown>;
}

/**
 * Validation result for hooks
 */
export interface HookValidationResult {
  allowed: boolean;
  riskScore: number;
  violations: string[];
  sanitizedPrompt?: string;
  action: "block" | "sanitize" | "warn" | "pass";
  gateResult?: {
    passed: boolean;
    failedGate?: string;
    failedControlId?: string;
    formatted: string;
  };
}
/**
 * Hook handler function type
 */
export type HookHandler<T> = (payload: T) => Promise<HookValidationResult>;
