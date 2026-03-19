/**
 * Runtime input validation middleware.
 * 
 * Validates prompt inputs at runtime to catch malformed or malicious content.
 */

import { SecurityMiddleware } from "../core/middleware.js";
import { SecurityContext } from "../core/context.js";
import { SecurityResult, SecurityIssue } from "../core/result.js";
import { CONTROL_CHARS } from "../scanner/patterns.js";

export class InputValidator extends SecurityMiddleware {
  private readonly maxLength: number;

  /**
   * @param maxLength - Maximum allowed prompt length (default: 10000)
   */
  constructor(maxLength: number = 10000) {
    super();
    this.maxLength = maxLength;
  }

  /**
   * Validate prompt input.
   */
  public async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    const issues: SecurityIssue[] = [];

    // Check for null bytes
    if (prompt.includes("\x00")) {
      issues.push({
        category: "null_byte",
        severity: "high",
        span: { start: prompt.indexOf("\x00"), end: prompt.indexOf("\x00") + 1 },
        recommendation: "Null bytes detected in prompt",
      });
    }

    // Check for control characters (except tab, newline, carriage return)
    const foundControlChars: string[] = [];
    for (const char of CONTROL_CHARS) {
      if (prompt.includes(char)) {
        foundControlChars.push(char);
      }
    }
    if (foundControlChars.length > 0) {
      issues.push({
        category: "control_chars",
        severity: "medium",
        span: { start: 0, end: prompt.length },
        recommendation: `Control characters detected: ${foundControlChars.map((c) => c.charCodeAt(0)).join(", ")}`,
      });
    }

    // Check encoding - verify valid UTF-8
    try {
      new TextEncoder().encode(prompt);
    } catch (e) {
      issues.push({
        category: "encoding",
        severity: "high",
        span: { start: 0, end: prompt.length },
        recommendation: `Invalid UTF-8 encoding: ${(e as Error).message}`,
      });
    }

    // Check length
    if (prompt.length > this.maxLength) {
      issues.push({
        category: "length_exceeded",
        severity: "medium",
        span: { start: 0, end: prompt.length },
        recommendation: `Prompt exceeds maximum length: ${prompt.length} > ${this.maxLength}`,
      });
    }

    // Check if prompt is empty or only whitespace
    if (!prompt.trim()) {
      issues.push({
        category: "empty_prompt",
        severity: "low",
        span: { start: 0, end: prompt.length },
        recommendation: "Prompt is empty or contains only whitespace",
      });
    }

    // Calculate risk score
    const riskScore = Math.min(issues.length * 0.4, 1.0);

    return new SecurityResult({
      prompt,
      allowed: issues.length === 0,
      riskScore,
      issues,
      metadata: {
        validation: "complete",
        promptLength: prompt.length,
        maxLength: this.maxLength,
      },
    });
  }
}
