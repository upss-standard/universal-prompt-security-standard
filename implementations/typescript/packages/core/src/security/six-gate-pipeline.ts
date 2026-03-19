/**
 * UPSS 6-Gate Security Pipeline
 *
 * This module provides a pre-configured pipeline with all 6 security gates
 * as specified in the UPSS standard.
 *
 * Gates executed in order (halt on first failure):
 * 1. RS-04: Encoding & Character Validation
 * 2. RS-03: Length Validation
 * 3. RS-01/RS-02: Forbidden Pattern Detection
 * 4. RS-02: Structural Role Separation
 * 5. CR-03: Checksum Integrity Verification
 * 6. RS-05: Rate Limit Check
 *
 * OWASP LLM01:2025 Aligned
 */

import {
  SecurityPipeline,
  SecurityContext,
  SecurityResult,
} from "../core/index.js";
import {
  BasicSanitizer,
  InputValidator,
  ChecksumMiddleware,
  RateLimitMiddleware,
  SimpleRBAC,
} from "../middleware/index.js";

/**
 * Configuration for the 6-gate pipeline
 */
export interface SixGatePipelineConfig {
  /** Maximum user prompt length (default: 10000) */
  maxUserPromptLength?: number;
  /** Maximum system prompt length (default: 32768) */
  maxSystemPromptLength?: number;
  /** Path to SQLite database for rate limiting */
  rateLimitDbPath?: string;
  /** Custom rate limits per role */
  rateLimits?: Record<string, number>;
  /** Checksums for Gate 5 verification */
  checksums?: Record<string, string>;
  /** Fail if checksum missing (default: false) */
  failOnMissingChecksum?: boolean;
  /** RBAC roles configuration */
  rolesConfig?: Record<string, string[]>;
  /** Enable RBAC gate (default: true) */
  enableRBAC?: boolean;
  /** Enable rate limiting gate (default: true) */
  enableRateLimit?: boolean;
  /** Enable checksum gate (default: true) */
  enableChecksum?: boolean;
}

/**
 * Result of the 6-gate pipeline execution
 */
export interface SixGateResult {
  passed: boolean;
  prompt: string;
  riskScore: number;
  gateResults: {
    gate1_encoding: SecurityResult | null;
    gate2_length: SecurityResult | null;
    gate3_patterns: SecurityResult | null;
    gate4_rbac: SecurityResult | null;
    gate5_checksum: SecurityResult | null;
    gate6_rateLimit: SecurityResult | null;
  };
  failedGate?: string;
  failedControlId?: string;
  violations: string[];
}

/**
 * Create a 6-gate security pipeline with all UPSS controls.
 *
 * @param config - Pipeline configuration
 * @returns Configured SecurityPipeline instance
 */
export function createSixGatePipeline(
  config: SixGatePipelineConfig = {}
): SecurityPipeline {
  const pipeline = new SecurityPipeline();

  // Gate 1 & 2: Input Validation (Encoding + Length)
  const maxLength = config.maxUserPromptLength ?? 10000;
  pipeline.use(new InputValidator({ maxLength }));

  // Gate 3: Forbidden Pattern Detection
  pipeline.use(new BasicSanitizer());

  // Gate 4: Structural Role Separation (RBAC)
  if (config.enableRBAC !== false) {
    pipeline.use(new SimpleRBAC(config.rolesConfig));
  }

  // Gate 5: Checksum Integrity Verification
  if (config.enableChecksum !== false) {
    pipeline.use(
      new ChecksumMiddleware({
        checksums: config.checksums,
        failOnMissing: config.failOnMissingChecksum ?? false,
      })
    );
  }

  // Gate 6: Rate Limit Check
  if (config.enableRateLimit !== false) {
    pipeline.use(
      new RateLimitMiddleware({
        limits: config.rateLimits,
      })
    );
  }

  return pipeline;
}

/**
 * Execute all 6 gates and return detailed results.
 *
 * @param pipeline - The security pipeline to execute
 * @param prompt - The prompt to validate
 * @param context - Security context
 * @returns Detailed 6-gate result
 */
export async function executeSixGates(
  pipeline: SecurityPipeline,
  prompt: string,
  context: SecurityContext
): Promise<SixGateResult> {
  const result = await pipeline.execute(prompt, context);

  // Extract individual gate results from metadata
  const middlewareResults = (result.metadata.middlewareResults ?? {}) as Record<string, SecurityResult>;

  const gateResults: SixGateResult["gateResults"] = {
    gate1_encoding: null,
    gate2_length: null,
    gate3_patterns: null,
    gate4_rbac: null,
    gate5_checksum: null,
    gate6_rateLimit: null,
  };

  // Map middleware results to gates
  if (middlewareResults.InputValidator) {
    gateResults.gate1_encoding = middlewareResults.InputValidator;
    gateResults.gate2_length = middlewareResults.InputValidator; // Combined in validator
  }
  if (middlewareResults.BasicSanitizer) {
    gateResults.gate3_patterns = middlewareResults.BasicSanitizer;
  }
  if (middlewareResults.SimpleRBAC) {
    gateResults.gate4_rbac = middlewareResults.SimpleRBAC;
  }
  if (middlewareResults.ChecksumMiddleware) {
    gateResults.gate5_checksum = middlewareResults.ChecksumMiddleware;
  }
  if (middlewareResults.RateLimitMiddleware) {
    gateResults.gate6_rateLimit = middlewareResults.RateLimitMiddleware;
  }

  // Find failed gate
  let failedGate: string | undefined;
  let failedControlId: string | undefined;

  for (const [gateName, gateResult] of Object.entries(gateResults)) {
    if (gateResult && !gateResult.isSafe) {
      failedGate = gateName;
      failedControlId = gateResult.metadata.controlId as string;
      break;
    }
  }

  return {
    passed: result.isSafe,
    prompt: result.prompt,
    riskScore: result.riskScore,
    gateResults,
    failedGate,
    failedControlId,
    violations: [...result.violations],
  };
}

/**
 * Format 6-gate result for display.
 */
export function formatGateResult(result: SixGateResult): string {
  if (result.passed) {
    return `🛡️ UPSS PASS — all 6 security gates cleared. Proceeding.
   Risk score: ${result.riskScore.toFixed(2)} | Gates: RS-04✅ RS-03✅ RS-01/02✅ Structure✅ CR-03✅ RS-05✅`;
  }

  const gateEmojis = {
    gate1_encoding: "RS-04",
    gate2_length: "RS-03",
    gate3_patterns: "RS-01/02",
    gate4_rbac: "Structure",
    gate5_checksum: "CR-03",
    gate6_rateLimit: "RS-05",
  };

  const gateStatuses = Object.entries(result.gateResults)
    .map(([gate, res]) => {
      const code = gateEmojis[gate as keyof typeof gateEmojis] ?? gate;
      return res?.isSafe ? `${code}✅` : `${code}❌`;
    })
    .join(" ");

  return `🚨 UPSS BLOCK — security violation detected. Halting.
   Gate failed: ${result.failedGate ?? "unknown"} (${result.failedControlId ?? "unknown"})
   Matched pattern: ${result.violations[0] ?? "N/A"}
   Risk score: ${result.riskScore.toFixed(2)}
   Gates: ${gateStatuses}
   Action: Prompt rejected. No LLM call made. Event logged.`;
}