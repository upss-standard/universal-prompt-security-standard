/**
 * Basic sanitization middleware for prompt injection prevention.
 * 
 * This module provides essential prompt sanitization to block common
 * injection patterns with minimal overhead.
 */

import { SecurityContext, SecurityResult } from "../core/models.js";
import { SecurityMiddleware } from "../core/middleware.js";

/**
 * Essential prompt sanitization middleware.
 * 
 * Blocks common prompt injection patterns with minimal configuration.
 * This should be the first middleware in most security pipelines.
 * 
 * Default patterns blocked:
 * - Instruction override attempts (ignore previous, disregard above)
 * - Role confusion (you are now, act as if)
 * - System prompt injection (system:, <|im_start|>)
 * - Delimiter injection attempts
 * 
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new BasicSanitizer());
 * 
 * // Or with custom patterns
 * pipeline.use(new BasicSanitizer({
 *   blockPatterns: [
 *     /custom_pattern_1/,
 *     /custom_pattern_2/
 *   ]
 * }));
 * ```
 */
export class BasicSanitizer extends SecurityMiddleware {
  // Default injection patterns to block
  static readonly DEFAULT_PATTERNS: RegExp[] = [
    // Instruction override
    /ignore\s+(previous|above|prior)\s+(instructions?|prompts?|commands?)/i,
    /disregard\s+(previous|above|all|everything)/i,
    /forget\s+(previous|above|all|everything)/i,
    // Role confusion
    /you\s+are\s+now/i,
    /act\s+as\s+if/i,
    /pretend\s+(to\s+be|you\s+are)/i,
    /simulate\s+(being|that\s+you)/i,
    // System prompt injection
    /new\s+instructions?:/i,
    /system\s*:\s*/i,
    /<\s*\|\s*im_start\s*\|\s*>/i,
    /<\s*\|\s*im_end\s*\|\s*>/i,
    // Delimiter injection
    /---\s*end\s+of\s+prompt/i,
    /```\s*system/i,
    // Privilege escalation
    /sudo\s+mode/i,
    /admin\s+mode/i,
    /developer\s+mode/i,
    /god\s+mode/i,
    /root\s+access/i,
  ];

  private readonly patterns: RegExp[];

  /**
   * Initialize the sanitizer.
   * 
   * @param options - Configuration options
   * @param options.blockPatterns - Custom patterns to block (replaces defaults if provided)
   */
  constructor(options?: { blockPatterns?: RegExp[] }) {
    super();
    this.patterns = options?.blockPatterns ?? BasicSanitizer.DEFAULT_PATTERNS;
  }

  /**
   * Scan prompt for injection patterns and sanitize if needed.
   * 
   * @param prompt - The prompt text to sanitize
   * @param context - Security context
   * @returns Promise resolving to SecurityResult with sanitized prompt and any violations
   */
  async process(
    prompt: string,
    _context: SecurityContext
  ): Promise<SecurityResult> {
    const violations: string[] = [];
    let cleanedPrompt = prompt;
    let matchesFound = 0;

    for (const pattern of this.patterns) {
      const matches = prompt.match(pattern);
      if (matches) {
        for (const match of matches) {
          matchesFound++;
          violations.push(`Injection pattern detected: '${match}'`);
          // Redact the matched pattern
          cleanedPrompt = cleanedPrompt.replace(match, "[REDACTED]");
        }
      }
    }

    // Calculate risk score based on number of violations
    // Each violation adds 0.3 to risk score, capped at 1.0
    const riskScore = Math.min(violations.length * 0.3, 1.0);

    return new SecurityResult(
      cleanedPrompt,
      violations.length === 0,
      riskScore,
      violations,
      {
        patternsChecked: this.patterns.length,
        matchesFound,
        sanitized: violations.length > 0,
      }
    );
  }
}
