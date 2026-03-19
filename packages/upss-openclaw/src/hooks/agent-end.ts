/**
 * Hook handler for agent:end.
 * 
 * Logs prompt usage metadata.
 */

import { LightweightAuditor } from "@upss/core";
import { SecurityContext } from "@upss/core";
import { UPSSConfig } from "../config/schema.js";

export interface AgentEndEvent {
  agent: {
    id: string;
    name: string;
  };
  prompt: {
    id: string;
    content: string;
  };
  context: {
    userId: string;
    metadata?: Record<string, unknown>;
  };
  result?: {
    success: boolean;
    error?: string;
  };
}

/**
 * Handle agent:end hook.
 * 
 * Logs prompt usage metadata for audit trail.
 */
export async function handleAgentEnd(
  event: AgentEndEvent,
  config: UPSSConfig
): Promise<void> {
  const { agent, prompt, context: ctx, result } = event;

  // Create auditor
  const logPath = `${config.rootDir}/logs/agent_audit.jsonl`;
  const auditor = new LightweightAuditor(logPath);

  const context = new SecurityContext({
    userId: ctx.userId,
    promptId: prompt.id,
    metadata: {
      ...ctx.metadata,
      agentId: agent.id,
      agentName: agent.name,
      success: result?.success ?? true,
      error: result?.error,
    },
  });

  // Log the prompt usage
  await auditor.process(prompt.content, context);
}
