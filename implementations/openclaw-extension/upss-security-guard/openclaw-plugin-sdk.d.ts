/**
 * Type declarations for Clawdbot/OpenClaw Plugin SDK
 * These types are provided by the OpenClaw runtime
 */

declare module "clawdbot/plugin-sdk" {
  export interface ClawdbotPluginApi {
    getConfig(): Record<string, unknown>;
    log(level: string, message: string, data?: Record<string, unknown>): void;
    emit(event: string, data: Record<string, unknown>): void;
  }

  export interface HookContext {
    userId: string;
    sessionId?: string;
    messageId?: string;
    timestamp: number;
    metadata?: Record<string, unknown>;
  }

  export interface MessagePreprocessedContext extends HookContext {
    message: string;
    channel?: string;
    sender?: string;
  }

  export interface BeforePromptBuildContext extends HookContext {
    systemPrompts: string[];
    toolPrompts: string[];
    userInput: string;
    promptRef?: string;
  }

  export interface HookResult {
    allow: boolean;
    reason?: string;
    metadata?: Record<string, unknown>;
    modifiedMessage?: string;
  }
}