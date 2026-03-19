/**
 * Context information for security operations.
 */

export type RiskLevel = "low" | "medium" | "high";
export type Environment = "development" | "staging" | "production";

export interface SecurityContextData {
  userId: string;
  promptId: string;
  riskLevel: RiskLevel;
  environment: Environment;
  metadata: Record<string, unknown>;
}

export class SecurityContext {
  public readonly userId: string;
  public readonly promptId: string;
  public readonly riskLevel: RiskLevel;
  public readonly environment: Environment;
  public readonly metadata: Record<string, unknown>;

  constructor(data: Partial<SecurityContextData> & { userId: string; promptId: string }) {
    this.userId = data.userId;
    this.promptId = data.promptId;
    this.riskLevel = data.riskLevel ?? "medium";
    this.environment = data.environment ?? "production";
    this.metadata = data.metadata ?? {};

    // Validate risk level
    const validLevels: RiskLevel[] = ["low", "medium", "high"];
    if (!validLevels.includes(this.riskLevel)) {
      throw new Error(
        `Invalid riskLevel: ${this.riskLevel}. Must be one of ${validLevels.join(", ")}`
      );
    }
  }

  public withMetadata(additional: Record<string, unknown>): SecurityContext {
    return new SecurityContext({
      userId: this.userId,
      promptId: this.promptId,
      riskLevel: this.riskLevel,
      environment: this.environment,
      metadata: { ...this.metadata, ...additional },
    });
  }
}
