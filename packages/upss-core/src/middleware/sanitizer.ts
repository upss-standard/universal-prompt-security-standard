/**
 * Basic sanitization middleware for prompt injection prevention.
 * 
 * Blocks common prompt injection patterns with minimal configuration.
 */

import { SecurityMiddleware } from "../core/middleware.js";
import { SecurityContext } from "../core/context.js";
import { SecurityResult, SecurityIssue } from "../core/result.js";
import { DEFAULT_INJECTION_PATTERNS } from "../scanner/patterns.js";

export class BasicSanitizer extends SecurityMiddleware {
  private readonly patterns: RegExp[];

  /**
   * @param blockPatterns - Custom patterns to block (replaces defaults if provided)
   */
  constructor(blockPatterns?: RegExp[]) {
    super();
    this.patterns = blockPatterns ?? DEFAULT_INJECTION_PATTERNS;
  }

  /**
   * Scan prompt for injection patterns and sanitize if needed.
   */
  public async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    const issues: SecurityIssue[] = [];
    let cleanedPrompt = prompt;
    let matchesFound = 0;

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(prompt)) !== null) {
        matchesFound++;
        const matchedText = match[0];

        issues.push({
          category: "injection_pattern",
          severity: "high",
          span: { start: match.index, end: match.index + matchedText.length },
          recommendation: `Detected injection pattern: '${matchedText}'`,
        });

        // Redact the matched pattern
        cleanedPrompt = cleanedPrompt.replace(matchedText, "[REDACTED]");
      }
    }

    // Calculate risk score based on number of violations
    // Each violation adds 0.3 to risk score, capped at 1.0
    const riskScore = Math.min(issues.length * 0.3, 1.0);

    return new SecurityResult({
      prompt: cleanedPrompt,
      allowed: issues.length === 0,
      riskScore,
      issues,
      metadata: {
        patternsChecked: this.patterns.length,
        matchesFound,
        sanitized: issues.length > 0,
      },
    });
  }
}
