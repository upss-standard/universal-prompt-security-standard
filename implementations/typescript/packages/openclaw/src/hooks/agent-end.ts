/**
 * agent_end hook implementation
 * 
 * Logs prompt usage metadata for audits and ToM integration.
 */

import { UPSSPluginConfig } from "../config/plugin.js";
import { AgentEndPayload } from "./types.js";
import { writeFileSync, appendFileSync, existsSync, mkdirSync } from "fs";
import { dirname, join } from "path";

/**
 * Create agent_end hook handler
 */
export function createAgentEndHook(config: UPSSPluginConfig) {
  return async (payload: AgentEndPayload): Promise<void> => {
    if (!config.enableAuditLogging) {
      return;
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType: "agent_end",
      userId: payload.userId,
      promptIds: payload.promptIds,
      riskScores: payload.riskScores,
      sanitized: payload.sanitized,
      blocked: payload.blocked,
      durationMs: payload.durationMs,
      ...payload.metadata,
    };

    const logPath = config.auditLogPath;
    if (logPath) {
      try {
        const dir = dirname(logPath);
        if (!existsSync(dir)) {
          mkdirSync(dir, { recursive: true });
        }
        appendFileSync(logPath, JSON.stringify(logEntry) + "\n");
      } catch (error) {
        console.error("Failed to write audit log:", error);
      }
    }

    // Emit for external observability (if configured)
    if (payload.metadata?.observabilityEmitter) {
      const emitter = payload.metadata.observabilityEmitter as (event: unknown) => void;
      emitter(logEntry);
    }
  };
}
