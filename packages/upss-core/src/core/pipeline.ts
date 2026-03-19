/**
 * Composable security middleware pipeline.
 */

import { SecurityMiddleware } from "./middleware.js";
import { SecurityContext } from "./context.js";
import { SecurityResult } from "./result.js";

/**
 * The pipeline executes middleware in sequence, allowing each to validate
 * and potentially modify the prompt. If any middleware marks the prompt as
 * unsafe, the pipeline stops execution.
 * 
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new BasicSanitizer());
 * pipeline.use(new LightweightAuditor());
 * pipeline.use(new SimpleRBAC());
 * 
 * const context = new SecurityContext({ userId: "alice", promptId: "greeting" });
 * const result = await pipeline.execute(userPrompt, context);
 * 
 * if (result.allowed) {
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

  /**
   * Add middleware to the pipeline.
   * 
   * Middleware is executed in the order it is added.
   * 
   * @param middleware - SecurityMiddleware instance to add
   * @returns Self for method chaining (fluent interface)
   */
  public use(middleware: SecurityMiddleware): this {
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
   * @returns SecurityResult with aggregated results from all middleware
   */
  public async execute(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    if (this.middlewares.length === 0) {
      // No middleware configured, return safe result
      return new SecurityResult({
        prompt,
        allowed: true,
        riskScore: 0.0,
        issues: [],
        metadata: { middlewareCount: 0 },
      });
    }

    let currentPrompt = prompt;
    const allIssues: SecurityResult["issues"] = [];
    let maxRiskScore = 0.0;
    const allMetadata: Record<string, unknown> = {};

    for (const middleware of this.middlewares) {
      const result = await middleware.process(currentPrompt, context);

      // Update prompt (middleware may have modified it)
      currentPrompt = result.prompt;

      // Aggregate issues
      allIssues.push(...result.issues);

      // Track maximum risk score
      maxRiskScore = Math.max(maxRiskScore, result.riskScore);

      // Merge metadata
      const middlewareName = middleware.constructor.name;
      allMetadata[middlewareName] = result.metadata;

      // Stop if middleware marked prompt as unsafe
      if (!result.allowed) {
        break;
      }
    }

    return new SecurityResult({
      prompt: currentPrompt,
      allowed: allIssues.length === 0,
      riskScore: maxRiskScore,
      issues: allIssues,
      metadata: {
        middlewareCount: this.middlewares.length,
        middlewareResults: allMetadata,
      },
    });
  }

  public toString(): string {
    const names = this.middlewares.map((m) => m.constructor.name);
    return `SecurityPipeline(middlewares=[${names.join(", ")}])`;
  }
}
