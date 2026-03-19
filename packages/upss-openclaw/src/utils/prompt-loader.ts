/**
 * Prompt loading utilities for OpenClaw plugin.
 */

import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
import { FilesystemStorage, PromptFile, PromptsConfig } from "@upss/core";
import { IntegrityError, NotFoundError } from "@upss/core";
import { createHash } from "crypto";

export interface LoadedPrompt extends PromptFile {
  checksum?: string;
  approved: boolean;
}

/**
 * Load prompts from the configured directory.
 */
export class PromptLoader {
  private storage: FilesystemStorage;
  private config: PromptsConfig | null = null;

  constructor(private rootDir: string) {
    this.storage = new FilesystemStorage(rootDir);
  }

  /**
   * Load prompts configuration.
   */
  public loadConfig(): PromptsConfig {
    this.config = this.storage.loadConfig();
    return this.config;
  }

  /**
   * Get the configuration (cached).
   */
  public getConfig(): PromptsConfig {
    if (!this.config) {
      return this.loadConfig();
    }
    return this.config;
  }

  /**
   * Load a specific prompt by name.
   */
  public loadPrompt(name: string, verifyChecksum: boolean = true): LoadedPrompt {
    const prompt = this.storage.loadPrompt(name);
    const config = this.getConfig();
    const promptConfig = config.prompts[name];

    const approved = promptConfig ? true : false;
    const checksum = promptConfig?.checksum;

    if (verifyChecksum && checksum) {
      const computed = this.computeChecksum(prompt.content);
      if (computed !== checksum) {
        throw new IntegrityError(
          `Checksum mismatch for prompt '${name}'`,
          { expected: checksum, computed }
        );
      }
    }

    return { ...prompt, checksum, approved };
  }

  /**
   * Load all available prompts.
   */
  public loadAllPrompts(): LoadedPrompt[] {
    const prompts = this.storage.loadAllPrompts();
    const config = this.getConfig();

    return prompts.map((prompt) => {
      const name = prompt.name;
      const promptConfig = config.prompts[name];
      return {
        ...prompt,
        checksum: promptConfig?.checksum,
        approved: promptConfig ? true : false,
      };
    });
  }

  /**
   * Compute SHA-256 checksum of prompt content.
   */
  public computeChecksum(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  /**
   * Resolve root directory path.
   */
  public static resolveRootDir(rootDir: string): string {
    if (rootDir.startsWith("~")) {
      const home = process.env.HOME || process.env.USERPROFILE || ".";
      return resolve(home, rootDir.slice(1));
    }
    return resolve(rootDir);
  }
}
