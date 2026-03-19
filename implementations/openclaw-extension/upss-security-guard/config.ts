/**
 * UPSS Security Guard Configuration
 */

export interface UPSSConfig {
  enabled?: boolean;
  riskThreshold?: number;
  defaultAction?: "block" | "sanitize" | "warn_only";
  maxUserPromptLength?: number;
  maxSystemPromptLength?: number;
  enforceChecksums?: boolean;
  enableRateLimit?: boolean;
  rateLimits?: {
    user?: number;
    developer?: number;
    admin?: number;
  };
  auditLogPath?: string;
}

export const DEFAULT_CONFIG: Required<UPSSConfig> = {
  enabled: true,
  riskThreshold: 0.7,
  defaultAction: "block",
  maxUserPromptLength: 10000,
  maxSystemPromptLength: 32768,
  enforceChecksums: true,
  enableRateLimit: true,
  rateLimits: {
    user: 60,
    developer: 100,
    admin: 1000,
  },
  auditLogPath: "~/.upss/logs/audit.jsonl",
};

export function loadConfig(overrides?: UPSSConfig): Required<UPSSConfig> {
  return {
    ...DEFAULT_CONFIG,
    ...overrides,
    rateLimits: {
      ...DEFAULT_CONFIG.rateLimits,
      ...overrides?.rateLimits,
    },
  };
}