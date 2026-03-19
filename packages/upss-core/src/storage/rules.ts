/**
 * Security rules loading and management.
 */

import { readFileSync, existsSync } from "fs";
import { NotFoundError, ConfigurationError } from "../core/exceptions.js";

export interface SecurityRule {
  id: string;
  description: string;
  severity: "high" | "medium" | "low";
  enabled: boolean;
  patterns?: string[];
  options?: Record<string, unknown>;
}

export interface RulesConfig {
  version: string;
  rules: SecurityRule[];
}

/**
 * Load security rules from a config file.
 */
export class RulesLoader {
  private readonly rules: Map<string, SecurityRule> = new Map();

  constructor(configPath?: string) {
    if (configPath) {
      this.loadFromFile(configPath);
    }
  }

  /**
   * Load rules from a JSON file.
   */
  public loadFromFile(configPath: string): void {
    if (!existsSync(configPath)) {
      throw new NotFoundError(`Rules config not found: ${configPath}`);
    }

    try {
      const content = readFileSync(configPath, "utf-8");
      const config = JSON.parse(content) as RulesConfig;

      for (const rule of config.rules) {
        this.rules.set(rule.id, rule);
      }
    } catch (e) {
      throw new ConfigurationError(
        `Failed to load rules from ${configPath}`,
        { path: configPath },
        e as Error
      );
    }
  }

  /**
   * Get a rule by ID.
   */
  public getRule(id: string): SecurityRule | undefined {
    return this.rules.get(id);
  }

  /**
   * Get all enabled rules.
   */
  public getEnabledRules(): SecurityRule[] {
    return Array.from(this.rules.values()).filter((r) => r.enabled);
  }

  /**
   * Get all rules.
   */
  public getAllRules(): SecurityRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Add a rule.
   */
  public addRule(rule: SecurityRule): void {
    this.rules.set(rule.id, rule);
  }

  /**
   * Remove a rule.
   */
  public removeRule(id: string): void {
    this.rules.delete(id);
  }
}
