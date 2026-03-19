/**
 * Lightweight audit logging middleware.
 * 
 * Logs all prompt access to a JSONL (JSON Lines) file for audit trail.
 */

import { writeFileSync, existsSync, mkdirSync, appendFileSync } from "fs";
import { dirname } from "path";
import { SecurityMiddleware } from "../core/middleware.js";
import { SecurityContext } from "../core/context.js";
import { SecurityResult } from "../core/result.js";

export interface AuditEntry {
  timestamp: string;
  userId: string;
  promptId: string;
  riskLevel: string;
  environment: string;
  promptLength: number;
  promptPreview: string;
  metadata: Record<string, unknown>;
}

export class LightweightAuditor extends SecurityMiddleware {
  private readonly logPath: string;

  /**
   * @param logPath - Path to the audit log file (JSONL format)
   */
  constructor(logPath: string = "logs/upss_audit.jsonl") {
    super();
    this.logPath = logPath;

    // Create log directory if it doesn't exist
    const dir = dirname(logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Create log file if it doesn't exist
    if (!existsSync(logPath)) {
      writeFileSync(logPath, "");
    }
  }

  /**
   * Log prompt access and pass through unchanged.
   */
  public async process(
    prompt: string,
    context: SecurityContext
  ): Promise<SecurityResult> {
    // Create audit entry
    const auditEntry: AuditEntry = {
      timestamp: new Date().toISOString(),
      userId: context.userId,
      promptId: context.promptId,
      riskLevel: context.riskLevel,
      environment: context.environment,
      promptLength: prompt.length,
      promptPreview: prompt.length > 100 ? prompt.substring(0, 100) : prompt,
      metadata: context.metadata,
    };

    // Append to log file (JSONL format - one JSON object per line)
    let logged = false;
    let error: string | null = null;

    try {
      appendFileSync(this.logPath, JSON.stringify(auditEntry) + "\n");
      logged = true;
    } catch (e) {
      error = (e as Error).message;
    }

    // Auditor never blocks - always returns safe
    return new SecurityResult({
      prompt,
      allowed: true,
      riskScore: 0.0,
      issues: [],
      metadata: {
        audited: logged,
        logPath: this.logPath,
        error,
      },
    });
  }

  /**
   * Query audit logs with filters.
   */
  public async queryLogs(
    userId?: string,
    promptId?: string,
    startTime?: Date,
    endTime?: Date,
    limit: number = 100
  ): Promise<AuditEntry[]> {
    if (!existsSync(this.logPath)) {
      return [];
    }

    const { readFileSync } = await import("fs");
    const results: AuditEntry[] = [];
    const content = readFileSync(this.logPath, "utf-8");
    const lines = content.split("\n").filter((line) => line.trim());

    for (const line of lines) {
      if (results.length >= limit) break;

      try {
        const entry = JSON.parse(line) as AuditEntry;

        if (userId && entry.userId !== userId) continue;
        if (promptId && entry.promptId !== promptId) continue;

        if (startTime || endTime) {
          try {
            const entryTime = new Date(entry.timestamp);
            if (startTime && entryTime < startTime) continue;
            if (endTime && entryTime > endTime) continue;
          } catch {
            continue;
          }
        }

        results.push(entry);
      } catch {
        // Skip malformed entries
        continue;
      }
    }

    return results;
  }
}
