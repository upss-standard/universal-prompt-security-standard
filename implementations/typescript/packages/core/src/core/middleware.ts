/**
 * Base middleware classes for UPSS v1.1.0 modular security architecture.
 */

import { SecurityContext, SecurityResult } from "./models.js";

/**
 * Abstract base class for all security middleware.
 * 
 * Security middleware processes prompts through a specific security check
 * and returns a result indicating whether the prompt is safe to use.
 * 
 * Middleware can:
 * - Validate prompt content
 * - Modify prompts (sanitization, redaction)
 * - Log access for audit
 * - Enforce policies
 * - Detect anomalies
 */
export abstract class SecurityMiddleware {
  /**
   * Process a prompt through this security middleware.
   * 
   * @param prompt - The prompt text to process
   * @param context - Security context for the operation
   * @returns Promise resolving to SecurityResult indicating whether the prompt is safe
   */
  abstract process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult>;

  toString(): string {
    return `${this.constructor.name}()`;
  }
}

/**
 * Composable security middleware pipeline.
 * 
 * The pipeline executes middleware in sequence, allowing each to validate
 * and potentially modify the prompt. If any middleware marks the prompt as
 * unsafe, the pipeline stops execution.
 * 
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new BasicSanitizer());
 * pipeline.use(new InputValidator());
 * pipeline.use(new LightweightAuditor());
 * 
 * const context = new SecurityContext({ userId: "alice", promptId: "greeting" });
 * const result = await pipeline.execute(userPrompt, context);
 * 
 * if (result.isSafe) {
 *   // Use the secure prompt
 *   const response = await llm.generate(result.prompt);
 * } else {
 *   // Handle security violations
 *   logSecurityEvent(result.violations);
 * }
 * ```
 */
export class SecurityPipeline {
  private middlewares: SecurityMiddleware[] = [];

  constructor() {
    this.middlewares = [];
  }

  /**
   * Add middleware to the pipeline.
   * 
   * Middleware is executed in the order it is added.
   * 
   * @param middleware - SecurityMiddleware instance to add
   * @returns Self for method chaining (fluent interface)
   * 
   * @example
   * ```typescript
   * pipeline.use(new BasicSanitizer()).use(new LightweightAuditor());
   * ```
   */
  use(middleware: SecurityMiddleware): this {
    this.middlewares.push(middleware);
    return this;
  }

  /**
   * Execute all middleware in the pipeline.
   * 
   * Middleware is executed sequentially. If any middleware marks the prompt
   * as unsafe, execution stops and the result is returned immediately.
   * 
   * @param prompt - The prompt text to process
   * @param context - Security context for the operation
   * @returns Promise resolving to SecurityResult with aggregated results
   */
  async execute(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    if (this.middlewares.length === 0) {
      // No middleware configured, return safe result
      return new SecurityResult(
        prompt,
        true,
        0.0,
        [],
        { middlewareCount: 0 }
      );
    }

    let currentPrompt = prompt;
    const allViolations: string[] = [];
    let maxRiskScore = 0.0;
    const allMetadata: Record<string, unknown> = {};

    for (const middleware of this.middlewares) {
      const result = await middleware.process(currentPrompt, context);

      // Update prompt (middleware may have modified it)
      currentPrompt = result.prompt;

      // Aggregate violations
      allViolations.push(...result.violations);

      // Track maximum risk score
      maxRiskScore = Math.max(maxRiskScore, result.riskScore);

      // Merge metadata
      const middlewareName = middleware.constructor.name;
      allMetadata[middlewareName] = result.metadata;

      // Stop if middleware marked prompt as unsafe
      if (!result.isSafe) {
        break;
      }
    }

    return new SecurityResult(
      currentPrompt,
      allViolations.length === 0,
      maxRiskScore,
      allViolations,
      {
        middlewareCount: this.middlewares.length,
        middlewareResults: allMetadata,
      }
    );
  }

  /**
   * Get middleware count
   */
  get middlewareCount(): number {
    return this.middlewares.length;
  }

  /**
   * Get list of middleware names in execution order
   */
  get middlewareNames(): string[] {
    return this.middlewares.map((m) => m.constructor.name);
  }

  toString(): string {
    return `SecurityPipeline(middlewares=${this.middlewareNames.join(", ")})`;
  }
}
