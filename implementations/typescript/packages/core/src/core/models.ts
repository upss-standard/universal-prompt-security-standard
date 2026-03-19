/**
 * Data models for UPSS.
 */

/**
 * Risk level enumeration
 */
export type RiskLevel = "low" | "medium" | "high" | "critical";

/**
 * Environment enumeration
 */
export type Environment = "development" | "staging" | "production";

/**
 * Security context for prompt processing operations.
 */
export interface SecurityContextParams {
  userId: string;
  promptId: string;
  riskLevel?: RiskLevel;
  environment?: Environment;
  metadata?: Record<string, unknown>;
}

/**
 * Security context information for security operations.
 */
export class SecurityContext {
  public readonly userId: string;
  public readonly promptId: string;
  public readonly riskLevel: RiskLevel;
  public readonly environment: Environment;
  public readonly metadata: Record<string, unknown>;

  private static readonly VALID_RISK_LEVELS: ReadonlySet<RiskLevel> = new Set([
    "low",
    "medium",
    "high",
    "critical",
  ]);

  private static readonly VALID_ENVIRONMENTS: ReadonlySet<Environment> = new Set([
    "development",
    "staging",
    "production",
  ]);

  constructor(params: SecurityContextParams) {
    this.userId = params.userId;
    this.promptId = params.promptId;
    this.riskLevel = params.riskLevel ?? "medium";
    this.environment = params.environment ?? "production";
    this.metadata = params.metadata ?? {};

    if (!SecurityContext.VALID_RISK_LEVELS.has(this.riskLevel)) {
      throw new Error(
        `Invalid riskLevel: ${this.riskLevel}. Must be one of: ${Array.from(
          SecurityContext.VALID_RISK_LEVELS
        ).join(", ")}`
      );
    }

    if (!SecurityContext.VALID_ENVIRONMENTS.has(this.environment)) {
      throw new Error(
        `Invalid environment: ${this.environment}. Must be one of: ${Array.from(
          SecurityContext.VALID_ENVIRONMENTS
        ).join(", ")}`
      );
    }
  }
}

/**
 * Result of security middleware processing.
 */
export class SecurityResult {
  public readonly prompt: string;
  public readonly isSafe: boolean;
  public readonly riskScore: number;
  public readonly violations: readonly string[];
  public readonly metadata: Record<string, unknown>;

  constructor(
    prompt: string,
    isSafe: boolean,
    riskScore: number,
    violations: readonly string[] | string[],
    metadata: Record<string, unknown> = {}
  ) {
    this.prompt = prompt;
    this.isSafe = isSafe;
    this.riskScore = riskScore;
    this.violations = violations;
    this.metadata = metadata;

    if (riskScore < 0 || riskScore > 1) {
      throw new Error(
        `riskScore must be between 0.0 and 1.0, got ${riskScore}`
      );
    }
  }
}

/**
 * Prompt content with metadata.
 */
export interface PromptContent {
  id: string;
  name: string;
  content: string;
  version: string;
  category: string;
  riskLevel: RiskLevel;
  checksum: string;
  createdAt: Date;
  updatedAt: Date;
  approved: boolean;
  approvedBy?: string;
  approvedDate?: Date;
  metadata: Record<string, unknown>;
}

/**
 * Audit log entry.
 */
export interface AuditEntry {
  timestamp: Date;
  eventType: string;
  userId: string;
  promptName: string;
  success: boolean;
  details: Record<string, unknown>;
}

/**
 * Report for batch migration operations.
 */
export interface MigrationReport {
  total: number;
  successful: number;
  failed: number;
  errors: Array<Record<string, unknown>>;
  details: Record<string, unknown>;
}
