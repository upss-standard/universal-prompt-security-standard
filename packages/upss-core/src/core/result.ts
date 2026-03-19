/**
 * Result of security middleware processing.
 */

export interface SecurityIssue {
  category: string;
  severity: "high" | "medium" | "low";
  span: { start: number; end: number };
  recommendation: string;
}

export interface SecurityResultData {
  prompt: string;
  allowed: boolean;
  riskScore: number;
  issues: SecurityIssue[];
  metadata: Record<string, unknown>;
}

export class SecurityResult {
  public readonly prompt: string;
  public readonly allowed: boolean;
  public readonly riskScore: number;
  public readonly issues: SecurityIssue[];
  public readonly metadata: Record<string, unknown>;

  constructor(data: SecurityResultData) {
    this.prompt = data.prompt;
    this.allowed = data.allowed;
    this.riskScore = data.riskScore;
    this.issues = data.issues;
    this.metadata = data.metadata;

    // Ensure riskScore is in valid range
    if (this.riskScore < 0.0 || this.riskScore > 1.0) {
      throw new Error(
        `riskScore must be between 0.0 and 1.0, got ${this.riskScore}`
      );
    }
  }

  public get isSafe(): boolean {
    return this.allowed;
  }

  public get violations(): string[] {
    return this.issues.map((issue) =>
      `${issue.severity.toUpperCase()}: ${issue.category} - ${issue.recommendation}`
    );
  }
}
