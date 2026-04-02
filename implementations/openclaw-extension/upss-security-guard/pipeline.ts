/**
 * UPSS 6-Gate Security Pipeline
 *
 * Creates a security pipeline with all 6 gates:
 * 1. RS-04: Encoding validation (InputValidator)
 * 2. RS-03: Length validation (InputValidator)
 * 3. RS-01/RS-02: Forbidden patterns (BasicSanitizer)
 * 4. RS-02: Structural role separation (SimpleRBAC)
 * 5. CR-03: Checksum verification (ChecksumMiddleware)
 * 6. RS-05: Rate limiting (RateLimitMiddleware)
 */

import type { UPSSConfig } from "./config.js";

// Simple implementations without external dependencies
// These will be replaced with @upss/core at runtime on the gateway

export interface PipelineResult {
  isSafe: boolean;
  riskScore: number;
  violations: string[];
  prompt: string;
  metadata: {
    gate?: string;
    controlId?: string;
    [key: string]: unknown;
  };
}

export interface PipelineContext {
  userId: string;
  promptId: string;
  metadata?: Record<string, unknown>;
}

// Forbidden patterns for Gate 3
const FORBIDDEN_PATTERNS = [
  /ignore\s+(previous|above|prior)\s+(instructions?|prompts?)/i,
  /disregard\s+(previous|above|all)/i,
  /you\s+are\s+now/i,
  /act\s+as\s+if/i,
  /pretend\s+(to\s+be|you\s+are)/i,
  /jailbreak/i,
  /DAN/i,
  /sudo\s+mode/i,
  /admin\s+mode/i,
  /god\s+mode/i,
  /system\s*:/i,
  /<\|im_start\|>/i,
  /<\|im_end\|>/i,
  /reveal\s+your\s+(instructions|system\s+prompt)/i,
  /repeat\s+everything\s+above/i,
];

// System-level tokens that should never appear in user content (Gate 4)
const SYSTEM_LEVEL_TOKENS = [
  /<\|im_start\|>/i,
  /<\|im_end\|>/i,
  /<\|system\|>/i,
  /<\|user\|>/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /^system:\s*/im,
  /###instruction/i,
  /---END OF SYSTEM PROMPT---/i,
  /IGNORE EVERYTHING/i,
  /\[hidden instruction\]/i,
  /\[secret task\]/i,
  /<!-- inject:/i,
  /\[SYSTEM OVERRIDE\]/i,
];

// In-memory rate limit storage (Gate 6)
// Note: In production, this should be shared across instances (Redis, etc.)
interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();
const RATE_LIMIT_WINDOW_MS = 60_000; // 60 seconds

/**
 * Create a 6-gate security pipeline
 */
export function createSecurityPipeline(config: Required<UPSSConfig>) {
  return {
    async execute(prompt: string, context: PipelineContext): Promise<PipelineResult> {
      const violations: string[] = [];
      let riskScore = 0;
      let failedGate: string | undefined;
      let failedControlId: string | undefined;

      // Gate 1: Encoding Validation (RS-04)
      if (prompt.includes("\x00")) {
        violations.push("Null bytes detected in prompt");
        failedGate = "Gate 1";
        failedControlId = "RS-04";
        riskScore = Math.max(riskScore, 0.8);
      }

      // Check for control characters
      for (let i = 0; i < 32; i++) {
        if (i !== 9 && i !== 10 && i !== 13 && prompt.includes(String.fromCharCode(i))) {
          violations.push(`Control character detected: ${i}`);
          failedGate = "Gate 1";
          failedControlId = "RS-04";
          riskScore = Math.max(riskScore, 0.8);
        }
      }

      // Gate 2: Length Validation (RS-03)
      if (prompt.length > config.maxUserPromptLength) {
        violations.push(`Prompt exceeds maximum length: ${prompt.length} > ${config.maxUserPromptLength}`);
        failedGate = "Gate 2";
        failedControlId = "RS-03";
        riskScore = Math.max(riskScore, 0.5);
      }

      // Gate 3: Forbidden Pattern Detection (RS-01/RS-02)
      for (const pattern of FORBIDDEN_PATTERNS) {
        const match = prompt.match(pattern);
        if (match) {
          violations.push(`Injection pattern detected: '${match[0]}'`);
          failedGate = "Gate 3";
          failedControlId = "RS-01";
          riskScore = Math.max(riskScore, 0.9);
        }
      }

      // Gate 4: Structural Role Separation (RS-02)
      // Check if user content contains system-level tokens
      if (violations.length === 0) {
        for (const pattern of SYSTEM_LEVEL_TOKENS) {
          const match = prompt.match(pattern);
          if (match) {
            violations.push(`RS-02: role boundary violation — user content contains system-level tokens: '${match[0]}'`);
            failedGate = "Gate 4";
            failedControlId = "RS-02";
            riskScore = Math.max(riskScore, 0.85);
            break;
          }
        }
      }

      // Gate 5: Checksum Verification (CR-03)
      if (config.enforceChecksums && context.metadata?.checksum) {
        const expectedChecksum = context.metadata.checksum as string;
        // In a full implementation, this would:
        // 1. Read the prompt artifact file
        // 2. Compute SHA-256 of content
        // 3. Compare with expectedChecksum
        // For now, we validate checksum format and log
        if (!expectedChecksum || expectedChecksum.length !== 64) {
          violations.push("CR-03: invalid checksum format in metadata");
          failedGate = "Gate 5";
          failedControlId = "CR-03";
          riskScore = Math.max(riskScore, 0.7);
        }
      }

      // Gate 6: Rate Limit Check (RS-05)
      if (config.enableRateLimit && violations.length === 0) {
        const role = (context.metadata?.role as string) || "user";
        const roleKey = role as "user" | "developer" | "admin";
        const limit = config.rateLimits?.[roleKey] ?? config.rateLimits?.user ?? 60;
        const now = Date.now();
        const key = `${context.userId}:${role}`;

        let entry = rateLimitStore.get(key);
        if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
          // New window
          entry = { count: 1, windowStart: now };
          rateLimitStore.set(key, entry);
        } else {
          entry.count++;
          if (entry.count > limit) {
            violations.push(`RS-05: rate limit exceeded for user ${context.userId} (role: ${role}) — ${entry.count}/${limit} requests in 60s`);
            failedGate = "Gate 6";
            failedControlId = "RS-05";
            riskScore = Math.max(riskScore, 0.6);
          }
        }
      }

      // Determine safety based on violations AND riskThreshold
      const isSafe = violations.length === 0 && riskScore < config.riskThreshold;

      return {
        isSafe,
        riskScore: isSafe ? 0 : Math.min(riskScore, 1.0),
        violations,
        prompt,
        metadata: {
          gate: failedGate,
          controlId: failedControlId,
          userId: context.userId,
          promptId: context.promptId,
        },
      };
    },
  };
}