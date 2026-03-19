/**
 * Simple role-based access control middleware.
 * 
 * Enforces access control based on user roles and prompt categories.
 */

import { SecurityMiddleware } from "../core/middleware.js";
import { SecurityContext } from "../core/context.js";
import { SecurityResult, SecurityIssue } from "../core/result.js";

export type Role = "admin" | "developer" | "user";
export type Category = "system" | "user" | "fallback" | "internal";

export type RolesConfig = Record<Role, Set<Category>>;

export class SimpleRBAC extends SecurityMiddleware {
  private readonly roles: Map<Role, Set<Category>>;

  /**
   * Default roles configuration.
   */
  public static readonly DEFAULT_ROLES: RolesConfig = {
    admin: new Set(["system", "user", "fallback", "internal"]),
    developer: new Set(["user", "fallback", "internal"]),
    user: new Set(["user"]),
  };

  /**
   * @param rolesConfig - Mapping of role names to sets of allowed categories
   */
  constructor(rolesConfig?: RolesConfig) {
    super();
    const entries = rolesConfig ?? SimpleRBAC.DEFAULT_ROLES;
    this.roles = new Map<Role, Set<Category>>([
      ["admin", entries.admin] as [Role, Set<Category>],
      ["developer", entries.developer] as [Role, Set<Category>],
      ["user", entries.user] as [Role, Set<Category>],
    ]);
  }

  /**
   * Check if user's role allows access to the prompt category.
   */
  public async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    // Get role and category from context metadata
    const metadata = context.metadata;
    const userRole = (metadata.role as Role) ?? "user";
    const promptCategory = (metadata.category as Category) ?? "user";

    // Get allowed categories for this role
    const allowedCategories = this.roles.get(userRole) ?? new Set();

    // Check if access is allowed
    if (!allowedCategories.has(promptCategory)) {
      const issues: SecurityIssue[] = [
        {
          category: "access_denied",
          severity: "high",
          span: { start: 0, end: prompt.length },
          recommendation: `Access denied: Role '${userRole}' cannot access category '${promptCategory}'`,
        },
      ];

      return new SecurityResult({
        prompt,
        allowed: false,
        riskScore: 1.0,
        issues,
        metadata: {
          rbacCheck: "failed",
          userRole,
          promptCategory,
          allowedCategories: Array.from(allowedCategories),
        },
      });
    }

    // Access allowed
    return new SecurityResult({
      prompt,
      allowed: true,
      riskScore: 0.0,
      issues: [],
      metadata: {
        rbacCheck: "passed",
        userRole,
        promptCategory,
      },
    });
  }

  /**
   * Add or update a role.
   */
  public addRole(role: Role, categories: Set<Category>): void {
    this.roles.set(role, categories);
  }

  /**
   * Remove a role.
   */
  public removeRole(role: Role): void {
    this.roles.delete(role);
  }

  /**
   * Get allowed categories for a role.
   */
  public getRolePermissions(role: Role): Set<Category> {
    return this.roles.get(role) ?? new Set();
  }
}
