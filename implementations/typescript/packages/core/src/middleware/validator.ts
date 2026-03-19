/**
 * Runtime input validation middleware.
 * 
 * This module provides validation of prompt inputs at runtime to catch
 * malformed or malicious content.
 */

import { SecurityContext, SecurityResult } from "../core/models.js";
import { SecurityMiddleware } from "../core/middleware.js";

/**
 * Runtime input validation middleware.
 * 
 * Validates prompt inputs for:
 * - Null bytes
 * - Control characters
 * - Encoding issues
 * - Length limits
 * 
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new InputValidator());
 * 
 * // Or with custom max length
 * pipeline.use(new InputValidator({ maxLength: 5000 }));
 * ```
 */
export class InputValidator extends SecurityMiddleware {
  private readonly maxLength: number;

  /**
   * Initialize the validator.
   * 
   * @param options - Configuration options
   * @param options.maxLength - Maximum allowed prompt length (default: 10000)
   */
  constructor(options?: { maxLength?: number }) {
    super();
    this.maxLength = options?.maxLength ?? 10000;
  }

  /**
   * Validate prompt input.
   * 
   * @param prompt - The prompt text to validate
   * @param context - Security context
   * @returns Promise resolving to SecurityResult indicating whether input is valid
   */
  async process(
    prompt: string,
    _context: SecurityContext
  ): Promise<SecurityResult> {
    const violations: string[] = [];

    // Check for null bytes
    if (prompt.includes("\x00")) {
      violations.push("Null bytes detected in prompt");
    }

    // Check for control characters (except tab, newline, carriage return)
    const controlChars = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i))
      .filter((c) => !"\t\n\r".includes(c));
    const foundControlChars = controlChars.filter((c) => prompt.includes(c));
    if (foundControlChars.length > 0) {
      violations.push(
        `Control characters detected: ${foundControlChars.map((c) => c.charCodeAt(0)).join(", ")}`
      );
    }

    // Check encoding - strings are always valid UTF-8 in JS/TS
    // This check is for API compatibility with Python version
    try {
      // Use TextEncoder to validate UTF-8
      new TextEncoder().encode(prompt);
    } catch (e) {
      const error = e as Error;
      violations.push(`Invalid UTF-8 encoding: ${error.message}`);
    }

    // Check length
    if (prompt.length > this.maxLength) {
      violations.push(
        `Prompt exceeds maximum length: ${prompt.length} > ${this.maxLength}`
      );
    }

    // Check if prompt is empty or only whitespace
    if (!prompt.trim()) {
      violations.push("Prompt is empty or contains only whitespace");
    }

    // Calculate risk score
    const riskScore = Math.min(violations.length * 0.4, 1.0);

    return new SecurityResult(
      prompt,
      violations.length === 0,
      riskScore,
      violations,
      {
        validation: "complete",
        promptLength: prompt.length,
        maxLength: this.maxLength,
      }
    );
  }
}
