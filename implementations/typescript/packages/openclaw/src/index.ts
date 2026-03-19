/**
 * UPSS OpenClaw Plugin
 * 
 * Universal Prompt Security Standard enforcement layer for OpenClaw.
 * 
 * Provides:
 * - Prompt validation and sanitization at runtime
 * - Integrity checks (hashes, signatures)
 * - Policy and rules evaluation
 * - Integration with OpenClaw hooks
 */

import { loadConfig, loadPromptsCatalog, UPSSPluginConfig, PromptsCatalog } from "./config/plugin.js";
import { createMessagePreprocessedHook } from "./hooks/message-preprocessed.js";
import { createBeforePromptBuildHook } from "./hooks/before-prompt-build.js";
import { createAgentEndHook } from "./hooks/agent-end.js";
import { createValidatePromptTool, ValidatePromptInput, ValidatePromptOutput } from "./tools/validate-prompt.js";

/**
 * Main plugin class for UPSS OpenClaw integration
 */
export class UPSSOpenClawPlugin {
  private readonly config: ReturnType<typeof loadConfig>;
  private readonly catalog: PromptsCatalog | null;

  constructor(config: UPSSPluginConfig = {}) {
    this.config = loadConfig(config);
    this.catalog = loadPromptsCatalog(this.config.promptsConfigPath);
    
    if (!this.catalog && this.config.strictMode) {
      throw new Error(
        `UPSS prompts catalog not found at ${this.config.promptsConfigPath}. ` +
        `Set strictMode: false to run in observe-only mode.`
      );
    }
  }

  /**
   * Get the message:preprocessed hook handler
   */
  get messagePreprocessed() {
    return createMessagePreprocessedHook(this.config);
  }

  /**
   * Get the before_prompt_build hook handler
   */
  get beforePromptBuild() {
    return createBeforePromptBuildHook(this.config);
  }

  /**
   * Get the agent_end hook handler
   */
  get agentEnd() {
    return createAgentEndHook(this.config);
  }

  /**
   * Get the UPSSValidatePrompt tool
   */
  get validatePromptTool() {
    return createValidatePromptTool(this.config);
  }

  /**
   * Get loaded prompts catalog
   */
  getPromptsCatalog(): PromptsCatalog | null {
    return this.catalog;
  }

  /**
   * Get plugin configuration
   */
  getConfig(): ReturnType<typeof loadConfig> {
    return this.config;
  }

  /**
   * Validate a prompt by ID (from catalog)
   */
  async validatePromptById(promptId: string): Promise<{ content: string | null; error?: string }> {
    if (!this.catalog) {
      return { content: null, error: "No prompts catalog loaded" };
    }

    const prompt = this.catalog.prompts.find((p) => p.id === promptId);
    if (!prompt) {
      return { content: null, error: `Prompt not found: ${promptId}` };
    }

    // Apply RBAC check if configured
    if (this.config.requireApproval && !prompt.approved) {
      return { content: null, error: `Prompt ${promptId} is not approved` };
    }

    return { content: prompt.content };
  }

  /**
   * Resolve a prompt reference (promptRef) to actual content
   */
  async resolvePromptRef(promptRef: string): Promise<string | null> {
    const result = await this.validatePromptById(promptRef);
    return result.content;
  }
}

// Re-export types
export type { UPSSPluginConfig } from "./config/plugin.js";
export type { ValidatePromptInput, ValidatePromptOutput } from "./tools/validate-prompt.js";
export type { HookValidationResult } from "./hooks/types.js";

// Default export
export default UPSSOpenClawPlugin;
