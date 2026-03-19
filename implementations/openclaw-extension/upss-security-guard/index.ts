/**
 * UPSS Security Guard - OpenClaw Plugin
 *
 * Native OpenClaw plugin that enforces the 6-gate UPSS security chain.
 *
 * Gates (executed in order, halt on first failure):
 * 1. RS-04: Encoding & Character Validation
 * 2. RS-03: Length Validation
 * 3. RS-01/RS-02: Forbidden Pattern Detection
 * 4. RS-02: Structural Role Separation
 * 5. CR-03: Checksum Integrity Verification
 * 6. RS-05: Rate Limit Check
 */

import { createSecurityPipeline } from "./pipeline.js";
import { loadConfig, UPSSConfig } from "./config.js";

// Module-level pipeline and config
let pipeline: ReturnType<typeof createSecurityPipeline> | null = null;
let pluginConfig: Required<UPSSConfig> | null = null;

// ── Hook Handlers ───────────────────────────────────────────────────────────

/**
 * Handle message:preprocessed event
 * Validates incoming user messages through 6-gate security chain
 */
export async function handleMessagePreprocessed(
  event: string,
  ctx: any
): Promise<{ allow: boolean; reason?: string; metadata?: any }> {
  if (!pipeline) {
    console.error("UPSS: Pipeline not initialized");
    return { allow: false, reason: "UPSS not initialized" };
  }

  const { message, userId, metadata } = ctx;

  const result = await pipeline.execute(message ?? "", {
    userId: userId ?? "anonymous",
    promptId: metadata?.promptId ?? "user-message",
    metadata: {
      role: metadata?.role ?? "user",
      category: "user",
    },
  });

  if (!result.isSafe) {
    console.log(
      `🚨 UPSS BLOCK — ${result.metadata.gate} (${result.metadata.controlId}): ${result.violations[0]}`
    );
    return {
      allow: false,
      reason: `UPSS BLOCK: ${result.violations[0]}`,
      metadata: {
        gate: result.metadata.gate,
        controlId: result.metadata.controlId,
        riskScore: result.riskScore,
        violations: result.violations,
      },
    };
  }

  return {
    allow: true,
    metadata: { riskScore: result.riskScore },
  };
}

/**
 * Handle prompt:build:before event
 * Validates the final prompt before sending to LLM
 */
export async function handleBeforePromptBuild(
  event: string,
  ctx: any
): Promise<{ allow: boolean; reason?: string; metadata?: any }> {
  if (!pipeline) {
    console.error("UPSS: Pipeline not initialized");
    return { allow: false, reason: "UPSS not initialized" };
  }

  const { systemPrompts = [], toolPrompts = [], userInput, userId, promptRef } = ctx;

  // Combine all prompt parts
  const combinedPrompt = [...systemPrompts, ...toolPrompts, userInput]
    .filter(Boolean)
    .join("\n\n");

  const result = await pipeline.execute(combinedPrompt, {
    userId: userId ?? "anonymous",
    promptId: promptRef ?? "final-prompt",
    metadata: {
      role: ctx.metadata?.role ?? "user",
      category: "user",
    },
  });

  if (!result.isSafe) {
    console.log(
      `🚨 UPSS BLOCK — ${result.metadata.gate} (${result.metadata.controlId}): ${result.violations[0]}`
    );
    return {
      allow: false,
      reason: `UPSS BLOCK: ${result.violations[0]}`,
      metadata: {
        gate: result.metadata.gate,
        controlId: result.metadata.controlId,
        riskScore: result.riskScore,
        violations: result.violations,
      },
    };
  }

  return {
    allow: true,
    metadata: {
      riskScore: result.riskScore,
    },
  };
}

// ── Plugin Registration ──────────────────────────────────────────────────────

/**
 * Registers the UPSS Security Guard plugin with OpenClaw.
 */
export function register(api: any): void {
  const cfg = api.pluginConfig ?? {};
  pluginConfig = loadConfig(cfg);

  // Check for existing registration
  if ((globalThis as any).__upssRegistered) {
    console.warn("UPSS Security Guard already registered, skipping");
    return;
  }

  try {
    // Initialize pipeline
    pipeline = createSecurityPipeline(pluginConfig);

    // Mark as registered
    (globalThis as any).__upssRegistered = true;

    console.log("🛡️ UPSS Security Guard plugin registered successfully");
    console.log(`   Risk threshold: ${pluginConfig.riskThreshold}`);
    console.log(`   Default action: ${pluginConfig.defaultAction}`);
    console.log(`   Max user prompt: ${pluginConfig.maxUserPromptLength} chars`);

    // Register hooks using api.on() pattern (like foundry)
    if (api.on) {
      api.on("message:preprocessed", handleMessagePreprocessed);
      console.log("  ✓ Hook: message:preprocessed");

      api.on("prompt:build:before", handleBeforePromptBuild);
      console.log("  ✓ Hook: prompt:build:before");
    }

    // Register tool for manual checks
    if (api.registerTool) {
      api.registerTool(
        {
          name: "upss_check",
          description:
            "Validate a prompt against the UPSS 6-gate security chain. Returns risk score and any violations.",
          inputSchema: {
            type: "object",
            properties: {
              prompt: {
                type: "string",
                description: "The prompt text to validate",
              },
              role: {
                type: "string",
                enum: ["admin", "developer", "user"],
                description: "User role for RBAC checks (default: user)",
              },
            },
            required: ["prompt"],
          },
          async execute(input: { prompt: string; role?: string }) {
            if (!pipeline) {
              return {
                error: "UPSS not initialized",
              };
            }

            const result = await pipeline.execute(input.prompt, {
              userId: "tool-check",
              promptId: "tool-check",
              metadata: { role: input.role ?? "user", category: "user" },
            });

            return {
              passed: result.isSafe,
              riskScore: result.riskScore,
              violations: result.violations,
              gate: result.metadata.gate,
              controlId: result.metadata.controlId,
              summary: result.isSafe
                ? "🛡️ UPSS PASS — all 6 security gates cleared"
                : `🚨 UPSS BLOCK — ${result.violations[0]}`,
            };
          },
        },
        { names: ["upss_check"] }
      );
      console.log("  ✓ Tool: upss_check");
    }
  } catch (error) {
    console.error("Failed to register UPSS Security Guard plugin:", error);
    throw error;
  }
}

/**
 * Get the current plugin config (for testing)
 */
export function getConfig(): Required<UPSSConfig> | null {
  return pluginConfig;
}