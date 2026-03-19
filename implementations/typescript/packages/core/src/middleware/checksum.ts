/**
 * Checksum integrity verification middleware (Gate 5 - CR-03).
 *
 * This module provides SHA-256 checksum verification for prompt artifacts
 * to detect supply-chain tampering.
 *
 * OWASP LLM01:2025 Control: CR-03 - Cryptographic Integrity Verification
 */

import { createHash } from "crypto";
import { SecurityContext, SecurityResult } from "../core/models.js";
import { SecurityMiddleware } from "../core/middleware.js";

/**
 * Checksum integrity verification middleware.
 *
 * Verifies SHA-256 checksums of prompt artifacts to detect supply-chain
 * tampering. This is Gate 5 in the UPSS security chain (CR-03).
 *
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new ChecksumMiddleware({
 *   checksumsPath: "~/.upss/checksums.json"
 * }));
 *
 * // Or with inline checksums
 * pipeline.use(new ChecksumMiddleware({
 *   checksums: {
 *     "system_prompt": "a1b2c3...",
 *     "assistant_prompt": "d4e5f6..."
 *   }
 * }));
 * ```
 */
export class ChecksumMiddleware extends SecurityMiddleware {
  private readonly checksums: Map<string, string> = new Map();
  private readonly failOnMissing: boolean;

  /**
   * Initialize checksum middleware.
   *
   * @param options - Configuration options
   * @param options.checksums - Direct mapping of prompt_id to SHA-256 checksum
   * @param options.failOnMissing - If true, block prompts without checksums (default: warn only)
   */
  constructor(options?: {
    checksums?: Record<string, string>;
    failOnMissing?: boolean;
  }) {
    super();

    this.failOnMissing = options?.failOnMissing ?? false;

    if (options?.checksums) {
      for (const [id, checksum] of Object.entries(options.checksums)) {
        this.checksums.set(id, checksum);
      }
    }
  }

  /**
   * Compute SHA-256 checksum of content.
   */
  private computeChecksum(content: string): string {
    return createHash("sha256").update(content, "utf8").digest("hex");
  }

  /**
   * Compute short hash for logging (first 16 chars of SHA-256).
   */
  private computePromptHash(prompt: string): string {
    return this.computeChecksum(prompt).slice(0, 16);
  }

  /**
   * Register a new checksum for a prompt.
   *
   * @param promptId - Identifier for the prompt
   * @param content - The prompt content to hash
   * @returns The computed SHA-256 checksum
   */
  registerChecksum(promptId: string, content: string): string {
    const checksum = this.computeChecksum(content);
    this.checksums.set(promptId, checksum);
    return checksum;
  }

  /**
   * Get all registered checksums.
   */
  getChecksums(): Record<string, string> {
    return Object.fromEntries(this.checksums);
  }

  /**
   * Verify prompt checksum against registered value.
   *
   * Gate 5 (CR-03) - Checksum Integrity Verification:
   * 1. Check if prompt_id has a registered checksum
   * 2. Compute SHA-256 of prompt content
   * 3. Compare against stored checksum
   * 4. BLOCK on mismatch (possible tampering)
   * 5. WARN if no checksum registered (unless failOnMissing=true)
   */
  async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    const promptId = context.promptId;
    const promptHash = this.computePromptHash(prompt);

    // Check if this prompt has a registered checksum
    if (!this.checksums.has(promptId)) {
      if (this.failOnMissing) {
        return new SecurityResult(
          prompt,
          false,
          0.5,
          [
            `CR-03: No checksum registered for prompt '${promptId}' ` +
              "- prompt artifact not UPSS-compliant",
          ],
          {
            gate: "Gate 5",
            controlId: "CR-03",
            promptId,
            promptHash,
            status: "missing_checksum",
          }
        );
      }

      // Warn but allow (soft failure)
      return new SecurityResult(prompt, true, 0.1, [], {
        gate: "Gate 5",
        controlId: "CR-03",
        promptId,
        promptHash,
        status: "no_checksum_warning",
      });
    }

    // Compute and compare checksum
    const expected = this.checksums.get(promptId)!;
    const actual = this.computeChecksum(prompt);

    if (actual !== expected) {
      // CRITICAL: Checksum mismatch - possible supply-chain tampering
      return new SecurityResult(
        prompt,
        false,
        1.0,
        [
          `CR-03: Checksum mismatch on '${promptId}' - ` +
            "possible supply-chain tampering detected",
        ],
        {
          gate: "Gate 5",
          controlId: "CR-03",
          promptId,
          promptHash,
          expectedChecksum: expected.slice(0, 16) + "...",
          actualChecksum: actual.slice(0, 16) + "...",
          status: "checksum_mismatch",
        }
      );
    }

    // Checksum verified successfully
    return new SecurityResult(prompt, true, 0.0, [], {
      gate: "Gate 5",
      controlId: "CR-03",
      promptId,
      promptHash,
      checksum: actual.slice(0, 16) + "...",
      status: "verified",
    });
  }
}