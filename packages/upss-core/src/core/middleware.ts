/**
 * Base middleware classes for UPSS v1.1.0 modular security architecture.
 */

import { SecurityContext } from "./context.js";
import { SecurityResult } from "./result.js";

/**
 * Abstract base class for all security middleware.
 * 
 * Security middleware processes prompts through a specific security check
 * and returns a result indicating whether the prompt is safe to use.
 */
export abstract class SecurityMiddleware {
  /**
   * Process a prompt through this security middleware.
   * 
   * @param prompt - The prompt text to process
   * @param context - Security context for the operation
   * @returns SecurityResult indicating whether the prompt is safe
   */
  public abstract process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult>;

  public toString(): string {
    return `${this.constructor.name}()`;
  }
}
