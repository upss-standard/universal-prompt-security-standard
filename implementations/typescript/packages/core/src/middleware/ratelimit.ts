/**
 * Rate limiting middleware (Gate 6 - RS-05).
 *
 * This module provides rate limiting to prevent abuse and brute-force attacks.
 * Uses in-memory storage by default, with optional SQLite persistence.
 *
 * OWASP LLM01:2025 Control: RS-05 - Rate Limiting
 */

import { SecurityContext, SecurityResult } from "../core/models.js";
import { SecurityMiddleware } from "../core/middleware.js";

/**
 * Rate limiting middleware.
 *
 * Enforces per-user request rate limits to prevent abuse. This is Gate 6
 * in the UPSS security chain (RS-05).
 *
 * Uses a sliding window algorithm. Default is in-memory storage.
 * For production, consider integrating SQLite or Redis.
 *
 * Default limits by role:
 * - user: 60 requests/minute
 * - developer: 100 requests/minute
 * - admin: 1000 requests/minute
 *
 * @example
 * ```typescript
 * const pipeline = new SecurityPipeline();
 * pipeline.use(new RateLimitMiddleware());
 *
 * // With custom limits
 * pipeline.use(new RateLimitMiddleware({
 *   limits: {
 *     user: 30,
 *     developer: 60,
 *     admin: 500
 *   }
 * }));
 * ```
 */
export class RateLimitMiddleware extends SecurityMiddleware {
  private readonly limits: Record<string, number>;
  private readonly windowSeconds: number;
  private readonly requestCounts: Map<string, { count: number; windowStart: number }> = new Map();

  static readonly DEFAULT_LIMITS: Record<string, number> = {
    user: 60,
    developer: 100,
    admin: 1000,
  };

  /**
   * Initialize rate limit middleware.
   *
   * @param options - Configuration options
   * @param options.limits - Custom limits per role (requests per minute)
   * @param options.windowSeconds - Time window for rate limiting (default: 60)
   */
  constructor(options?: {
    limits?: Record<string, number>;
    windowSeconds?: number;
  }) {
    super();

    this.limits = { ...RateLimitMiddleware.DEFAULT_LIMITS, ...options?.limits };
    this.windowSeconds = options?.windowSeconds ?? 60;
  }

  /**
   * Get user role from context metadata.
   */
  private getUserRole(context: SecurityContext): string {
    return (context.metadata?.role as string) ?? "user";
  }

  /**
   * Get request limit for a role.
   */
  private getLimitForRole(role: string): number {
    return this.limits[role] ?? this.limits.user;
  }

  /**
   * Get current time window start timestamp.
   */
  private getCurrentWindow(): number {
    const now = Date.now() / 1000;
    return now - (now % this.windowSeconds);
  }

  /**
   * Increment request count for user in current window.
   */
  private incrementCount(userId: string): number {
    const windowStart = this.getCurrentWindow();
    const key = `${userId}:${windowStart}`;

    const entry = this.requestCounts.get(key);
    if (entry && entry.windowStart === windowStart) {
      entry.count++;
      return entry.count;
    }

    // Clean up old entries
    this.cleanupOldWindows(windowStart);

    // Create new entry
    this.requestCounts.set(key, { count: 1, windowStart });
    return 1;
  }

  /**
   * Clean up entries from old time windows.
   */
  private cleanupOldWindows(currentWindow: number): void {
    const cutoff = currentWindow - this.windowSeconds * 2;
    for (const [key, entry] of this.requestCounts.entries()) {
      if (entry.windowStart < cutoff) {
        this.requestCounts.delete(key);
      }
    }
  }

  /**
   * Check and enforce rate limits.
   *
   * Gate 6 (RS-05) - Rate Limit Check:
   * 1. Get user role from context metadata
   * 2. Determine requests-per-minute limit for role
   * 3. Increment request count for current window
   * 4. If limit exceeded → BLOCK temporarily
   */
  async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    const userId = context.userId;
    const role = this.getUserRole(context);
    const limit = this.getLimitForRole(role);

    const currentCount = this.incrementCount(userId);

    if (currentCount > limit) {
      // Rate limit exceeded
      return new SecurityResult(
        prompt,
        false,
        0.7,
        [
          `RS-05: Rate limit exceeded for user ${userId} ` +
            `(${currentCount}/${limit} requests in last ${this.windowSeconds}s)`,
        ],
        {
          gate: "Gate 6",
          controlId: "RS-05",
          userId,
          role,
          currentCount,
          limit,
          windowSeconds: this.windowSeconds,
          status: "rate_limited",
        }
      );
    }

    // Request allowed
    return new SecurityResult(prompt, true, 0.0, [], {
      gate: "Gate 6",
      controlId: "RS-05",
      userId,
      role,
      currentCount,
      limit,
      windowSeconds: this.windowSeconds,
      status: "passed",
    });
  }

  /**
   * Reset rate limit state for a user.
   */
  resetUser(userId: string): void {
    for (const key of this.requestCounts.keys()) {
      if (key.startsWith(`${userId}:`)) {
        this.requestCounts.delete(key);
      }
    }
  }

  /**
   * Get rate limit status for a user.
   */
  getUserStatus(userId: string): {
    currentCount: number;
    limit: number;
    remaining: number;
  } {
    const windowStart = this.getCurrentWindow();
    const key = `${userId}:${windowStart}`;

    const entry = this.requestCounts.get(key);
    const currentCount = entry?.count ?? 0;
    const limit = this.limits.user;

    return {
      currentCount,
      limit,
      remaining: Math.max(0, limit - currentCount),
    };
  }
}