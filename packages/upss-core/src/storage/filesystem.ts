/**
 * Filesystem-based prompt storage.
 */

import { readFileSync, existsSync, readdirSync } from "fs";
import { join, basename } from "path";
import { NotFoundError, StorageError } from "../core/exceptions.js";

export interface PromptFile {
  name: string;
  content: string;
  path: string;
}

export interface PromptsConfig {
  version: string;
  prompts: Record<string, { path: string; checksum?: string }>;
}

/**
 * Load prompts from a directory.
 */
export class FilesystemStorage {
  private readonly rootDir: string;

  constructor(rootDir: string) {
    this.rootDir = rootDir;
  }

  /**
   * Load a prompt by name.
   */
  public loadPrompt(name: string): PromptFile {
    const path = join(this.rootDir, `${name}.txt`);

    if (!existsSync(path)) {
      throw new NotFoundError(`Prompt '${name}' not found at ${path}`);
    }

    try {
      const content = readFileSync(path, "utf-8");
      return { name, content, path };
    } catch (e) {
      throw new StorageError(
        `Failed to read prompt '${name}'`,
        { path },
        e as Error
      );
    }
  }

  /**
   * Load all prompts from the root directory.
   */
  public loadAllPrompts(): PromptFile[] {
    if (!existsSync(this.rootDir)) {
      return [];
    }

    const files = readdirSync(this.rootDir).filter(
      (f) => f.endsWith(".txt") || f.endsWith(".md")
    );

    return files.map((file) => {
      const name = basename(file, ".txt");
      const path = join(this.rootDir, file);
      const content = readFileSync(path, "utf-8");
      return { name, content, path };
    });
  }

  /**
   * Load prompts config file.
   */
  public loadConfig(): PromptsConfig {
    const configPath = join(this.rootDir, "prompts.json");

    if (!existsSync(configPath)) {
      return { version: "1.0.0", prompts: {} };
    }

    try {
      const content = readFileSync(configPath, "utf-8");
      return JSON.parse(content) as PromptsConfig;
    } catch (e) {
      throw new StorageError(
        "Failed to parse prompts.json",
        { path: configPath },
        e as Error
      );
    }
  }
}
