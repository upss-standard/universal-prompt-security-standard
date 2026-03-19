/**
 * Simple role-based access control middleware.
 * 
 * This module provides basic RBAC without requiring complex infrastructure.
 */

import { SecurityContext, SecurityResult } from "../core/models.js";
import { SecurityMiddleware } from "../core/middleware.js";

/**
 * Role configuration mapping role names to allowed prompt categories.
 */
export type RolesConfig = Record<string, Set<string>>;

/**
 * Simple role-based access control middleware.
 * 
 * Enforces access control based on user roles and prompt categories.
 * Uses a simple mapping of roles to allowed categories.
 * 
 * Default roles:
 * - admin: Can access all prompt categories
 * - developer: Can access user and fallback prompts
 * - user: Can only access user prompts
 * 
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new SimpleRBAC());
 * 
 * // Or with custom roles
 * pipeline.use(new SimpleRBAC({
 *   rolesConfig: {
 *     admin: new Set(["system", "user", "fallback"]),
 *     developer: new Set(["user", "fallback"]),
 *     user: new Set(["user"])
 *   }
 * }));
 * 
 * // Use with context metadata
 * const context = new SecurityContext({
 *   userId: "alice",
 *   promptId: "system-prompt",
 *   metadata: { role: "user", category: "system" }
 * });
 * const result = await pipeline.execute(prompt, context);
 * ```
 */
export class SimpleRBAC extends SecurityMiddleware {
  static readonly DEFAULT_ROLES: RolesConfig = {
    admin: new Set(["system", "user", "fallback", "internal"]),
    developer: new Set(["user", "fallback", "internal"]),
    user: new Set(["user"]),
  };

  private readonly roles: RolesConfig;

  /**
   * Initialize RBAC middleware.
   * 
   * @param options - Configuration options
   * @param options.rolesConfig - Mapping of role names to sets of allowed categories
   */
  constructor(options?: { rolesConfig?: RolesConfig }) {
    super();
    this.roles = options?.rolesConfig ?? SimpleRBAC.DEFAULT_ROLES;
  }

  /**
   * Check if user's role allows access to the prompt category.
   * 
   * @param prompt - The prompt text
   * @param context - Security context (must include 'role' and 'category' in metadata)
   * @returns Promise resolving to SecurityResult indicating whether access is allowed
   */
  async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    // Get role and category from context metadata
    const metadata = context.metadata;
    const userRole = (metadata?.role as string) ?? "user";
    const promptCategory = (metadata?.category as string) ?? "user";

    // Get allowed categories for this role
    const allowedCategories = this.roles[userRole] ?? new Set();

    // Check if access is allowed
    if (!allowedCategories.has(promptCategory)) {
      return new SecurityResult(
        prompt,
        false,
        1.0,
        [
          `Access denied: Role '${userRole}' cannot access category '${promptCategory}'`,
        ],
        {
          rbacCheck: "failed",
          userRole,
          promptCategory,
          allowedCategories: Array.from(allowedCategories),
        }
      );
    }

    // Access allowed
    return new SecurityResult(
      prompt,
      true,
      0.0,
      [],
      {
        rbacCheck: "passed",
        userRole,
        promptCategory,
      }
    );
  }

  /**
   * Add or update a role.
   * 
   * @param role - Role name
   * @param categories - Set of allowed categories for this role
   */
  addRole(role: string, categories: Set<string>): void {
    this.roles[role] = categories;
  }

  /**
   * Remove a role.
   * 
   * @param role - Role name to remove
   */
  removeRole(role: string): void {
    delete this.roles[role];
  }

  /**
   * Get allowed categories for a role.
   * 
   * @param role - Role name
   * @returns Set of allowed categories, or empty set if role doesn't exist
   */
  getRolePermissions(role: string): Set<string> {
    return this.roles[role] ?? new Set();
  }
}
