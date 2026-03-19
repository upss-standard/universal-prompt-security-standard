/**
 * UPSS OpenClaw Plugin
 * 
 * Universal Prompt Security Standard enforcement layer for OpenClaw.
 * 
 * This plugin provides:
 * - Hook handlers for message validation
 * - Security pipeline for prompt sanitization
 * - Tools for prompt validation
 */

import { UPSSConfigSchema, DEFAULT_UPSS_CONFIG, UPSSConfig } from "./config/schema.js";
import { handleMessageReceived } from "./hooks/message-received.js";
import { handleBeforePromptBuild } from "./hooks/before-prompt-build.js";
import { handleAgentEnd } from "./hooks/agent-end.js";
import { validatePrompt } from "./tools/validate-prompt.js";
import { PromptLoader } from "./utils/prompt-loader.js";

/**
 * UPSS OpenClaw Plugin
 */
export class UPSSOpenClawPlugin {
  public readonly name = "upss-security";
  public readonly version = "1.1.0";
  
  private config: UPSSConfig;
  private promptLoader: PromptLoader | null = null;

  constructor(config: Partial<UPSSConfig> = {}) {
    this.config = { ...DEFAULT_UPSS_CONFIG, ...config };
    
    // Validate config
    const parsed = UPSSConfigSchema.safeParse(this.config);
    if (!parsed.success) {
      if (this.config.strictMode) {
        throw new Error(`Invalid UPSS config: ${parsed.error}`);
      }
      console.warn(`Invalid UPSS config, using defaults: ${parsed.error}`);
      this.config = DEFAULT_UPSS_CONFIG;
    }
  }

  /**
   * Initialize the plugin.
   */
  public async init(api: unknown): Promise<void> {
    // Initialize prompt loader
    const rootDir = PromptLoader.resolveRootDir(this.config.rootDir);
    this.promptLoader = new PromptLoader(rootDir);

    // Register hooks
    this.registerHooks(api);
  }

  /**
   * Register OpenClaw hooks.
   */
  private registerHooks(api: unknown): void {
    // Cast api to any for now - actual OpenClaw SDK types would be used in production
    const openclawApi = api as {
      on: (event: string, handler: (data: unknown) => Promise<unknown>) => void;
      tool: (name: string, handler: (input: unknown) => Promise<unknown>) => void;
    };

    // Register message:received hook
    openclawApi.on("message:received", async (data: unknown) => {
      return handleMessageReceived(data as Parameters<typeof handleMessageReceived>[0], this.config);
    });

    // Register before_prompt_build hook
    openclawApi.on("before_prompt_build", async (data: unknown) => {
      return handleBeforePromptBuild(data as Parameters<typeof handleBeforePromptBuild>[0], this.config);
    });

    // Register agent:end hook
    openclawApi.on("agent:end", async (data: unknown) => {
      return handleAgentEnd(data as Parameters<typeof handleAgentEnd>[0], this.config);
    });

    // Register upss_validate_prompt tool
    openclawApi.tool("upss_validate_prompt", async (input: unknown) => {
      return validatePrompt(input as Parameters<typeof validatePrompt>[0]);
    });
  }

  /**
   * Get the configuration.
   */
  public getConfig(): UPSSConfig {
    return this.config;
  }

  /**
   * Validate the prompt catalog.
   */
  public validateCatalog(): { valid: boolean; errors: string[] } {
    if (!this.promptLoader) {
      return { valid: false, errors: ["Plugin not initialized"] };
    }

    const errors: string[] = [];

    try {
      const config = this.promptLoader.loadConfig();
      const prompts = this.promptLoader.loadAllPrompts();

      // Check that all configured prompts exist
      for (const [name, promptConfig] of Object.entries(config.prompts)) {
        const exists = prompts.some((p) => p.name === name);
        if (!exists) {
          errors.push(`Configured prompt '${name}' not found in directory`);
        }

        // Verify checksums if enforceChecksums is enabled
        if (this.config.enforceChecksums && promptConfig.checksum) {
          try {
            this.promptLoader.loadPrompt(name, true);
          } catch (e) {
            errors.push(`Checksum verification failed for '${name}': ${(e as Error).message}`);
          }
        }
      }
    } catch (e) {
      errors.push(`Failed to load config: ${(e as Error).message}`);
    }

    return { valid: errors.length === 0, errors };
  }
}

/**
 * Create a new UPSS plugin instance.
 */
export function createUPSSPlugin(config?: Partial<UPSSConfig>): UPSSOpenClawPlugin {
  return new UPSSOpenClawPlugin(config);
}

// Export all components
export { handleMessageReceived } from "./hooks/message-received.js";
export { handleBeforePromptBuild } from "./hooks/before-prompt-build.js";
export { handleAgentEnd } from "./hooks/agent-end.js";
export { validatePrompt } from "./tools/validate-prompt.js";
export { UPSSConfig, UPSSConfigSchema, DEFAULT_UPSS_CONFIG } from "./config/schema.js";
export { PromptLoader } from "./utils/prompt-loader.js";
