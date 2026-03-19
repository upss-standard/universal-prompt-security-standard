/**
 * UPSS OpenClaw Plugin Configuration
 */

import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { ConfigurationError } from "@upss/core";

/**
 * Plugin configuration options
 */
export interface UPSSPluginConfig {
  /** Root directory for UPSS artifacts (default: ~/.openclaw/upss) */
  rootDir?: string;
  /** Path to prompts.json configuration */
  promptsConfigPath?: string;
  /** Whether to enforce checksum verification */
  enforceChecksums?: boolean;
  /** Whether to require approval metadata */
  requireApproval?: boolean;
  /** Whether to fail gateway startup on config errors */
  strictMode?: boolean;
  /** Default action when validation fails: 'block' | 'sanitize' | 'warn_only' */
  defaultAction?: "block" | "sanitize" | "warn_only";
  /** Risk score threshold (0-1) for blocking prompts */
  riskThreshold?: number;
  /** Maximum user prompts length */
  maxUserPromptLength?: number;
  /** Maximum system prompts length */
  maxSystemPromptLength?: number;
  /** Enable audit logging */
  enableAuditLogging?: boolean;
  /** Path for audit logs */
  auditLogPath?: string;
}

/**
 * Default plugin configuration
 */
export const DEFAULT_CONFIG: Required<UPSSPluginConfig> = {
  rootDir: "~/.openclaw/upss",
  promptsConfigPath: "~/.openclaw/upss/prompts.json",
  enforceChecksums: true,
  requireApproval: true,
  strictMode: true,
  defaultAction: "block",
  riskThreshold: 0.7,
  maxUserPromptLength: 10000,
  maxSystemPromptLength: 32768,
  enableAuditLogging: true,
  auditLogPath: "~/.openclaw/upss/logs/audit.jsonl",
};

/**
 * Expand tilde paths to home directory
 */
function expandPath(path: string): string {
  if (path.startsWith("~/")) {
    return join(process.env.HOME ?? "", path.slice(2));
  }
  return path;
}

/**
 * Load and validate plugin configuration
 */
export function loadConfig(config: UPSSPluginConfig = {}): Required<UPSSPluginConfig> {
  const merged = { ...DEFAULT_CONFIG, ...config };
  
  // Expand paths
  merged.rootDir = expandPath(merged.rootDir);
  merged.promptsConfigPath = expandPath(merged.promptsConfigPath);
  merged.auditLogPath = expandPath(merged.auditLogPath);
  
  // Validate
  if (merged.riskThreshold < 0 || merged.riskThreshold > 1) {
    throw new ConfigurationError(
      "riskThreshold must be between 0 and 1",
      { riskThreshold: merged.riskThreshold }
    );
  }
  
  if (!["block", "sanitize", "warn_only"].includes(merged.defaultAction)) {
    throw new ConfigurationError(
      "defaultAction must be 'block', 'sanitize', or 'warn_only'",
      { defaultAction: merged.defaultAction }
    );
  }
  
  return merged;
}

/**
 * Load prompts configuration from JSON file
 */
export interface PromptsCatalog {
  version: string;
  prompts: PromptDefinition[];
  rules?: RulesDefinition;
}

export interface PromptDefinition {
  id: string;
  name: string;
  content: string;
  category: "system" | "user" | "fallback" | "internal";
  version: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  checksum?: string;
  approved: boolean;
  approvedBy?: string;
  approvedDate?: string;
  metadata?: Record<string, unknown>;
}

export interface RulesDefinition {
  allowedVariables?: string[];
  allowedSources?: string[];
  blockedPatterns?: string[];
  maxLength?: number;
}

export function loadPromptsCatalog(configPath: string): PromptsCatalog | null {
  if (!existsSync(configPath)) {
    return null;
  }
  
  try {
    const content = readFileSync(configPath, "utf-8");
    return JSON.parse(content) as PromptsCatalog;
  } catch (error) {
    throw new ConfigurationError(
      `Failed to load prompts catalog: ${(error as Error).message}`,
      { configPath }
    );
  }
}
