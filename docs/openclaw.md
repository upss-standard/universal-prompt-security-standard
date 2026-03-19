# UPSS OpenClaw Plugin

This document describes how to integrate the Universal Prompt Security Standard (UPSS) with OpenClaw using the Node.js plugin.

## Installation

### Prerequisites

- Node.js 18+
- OpenClaw SDK installed

### Install Packages

```bash
# Install core package
cd packages/upss-core
npm install
npm run build

# Install plugin package
cd ../upss-openclaw
npm install
npm run build
```

## Quick Start

```typescript
import { createUPSSPlugin } from "@upss/openclaw";

const upss = createUPSSPlugin({
  rootDir: "~/.openclaw/upss",
  strictMode: true,
  riskThreshold: 0.7,
  defaultAction: "block",
});

await upss.init(openclawApi);
```

## Configuration

### UPSSConfig

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rootDir` | string | `"~/.openclaw/upss"` | Root directory for UPSS data |
| `promptsConfigPath` | string | `"prompts.json"` | Path to prompts config |
| `enforceChecksums` | boolean | `true` | Verify SHA-256 checksums |
| `requireApproval` | boolean | `false` | Require manual approval |
| `strictMode` | boolean | `false` | Fail on config errors |
| `defaultAction` | `"block"` \| `"sanitize"` \| `"warn_only"` | `"block"` | Action on violation |
| `riskThreshold` | number | `0.7` | Risk score threshold (0-1) |

## Hooks

The plugin registers these hooks with OpenClaw:

### message:received

Validates incoming user messages and computes risk score.

```typescript
// Event payload
{
  message: {
    content: string;
    userId: string;
    metadata?: Record<string, unknown>;
  }
}

// Result
{
  allowed: boolean;
  riskScore: number;
  issues: SecurityIssue[];
  sanitizedContent?: string;
}
```

### before_prompt_build

Validates the final prompt before it's sent to the LLM.

```typescript
// Event payload
{
  prompt: {
    systemPrompt: string;
    userInput: string;
  };
  context: {
    userId: string;
    promptId: string;
    metadata?: Record<string, unknown>;
  };
}

// Result
{
  action: "block" | "sanitize" | "pass";
  sanitizedPrompt?: string;
  riskScore: number;
  issues: SecurityIssue[];
}
```

### agent:end

Logs prompt usage metadata for audit trail.

```typescript
// Event payload
{
  agent: { id: string; name: string };
  prompt: { id: string; content: string };
  context: { userId: string; metadata?: Record<string, unknown> };
  result?: { success: boolean; error?: string };
}
```

## Tools

### upss_validate_prompt

Validates a prompt against UPSS security rules.

```typescript
// Input
{
  prompt: string;
  role?: "user" | "system" | "developer";
  context?: Record<string, unknown>;
}

// Output
{
  allowed: boolean;
  riskScore: number;
  issues: Array<{
    category: string;
    severity: "high" | "medium" | "low";
    span: { start: number; end: number };
    recommendation: string;
  }>;
  sanitizedPrompt?: string;
}
```

## Security Gates

The plugin implements the 6-gate security chain:

| Gate | Control | Attack Prevented |
|------|---------|------------------|
| 1 | RS-04 | Null byte injection, control char exploits |
| 2 | RS-03 | Resource exhaustion, oversized prompt DoS |
| 3 | RS-01, RS-02 | Direct injection, jailbreak, privilege escalation |
| 4 | RS-02 | Indirect injection, role boundary violations |
| 5 | CR-03 | Supply-chain tampering |
| 6 | RS-05 | Rate-based abuse |

## Using Without OpenClaw

You can also use the core functionality directly:

```typescript
import { SecurityPipeline, BasicSanitizer, InputValidator, SecurityContext } from "@upss/core";

const pipeline = new SecurityPipeline()
  .use(new InputValidator())
  .use(new BasicSanitizer());

const context = new SecurityContext({
  userId: "user",
  promptId: "test",
});

const result = await pipeline.execute(userPrompt, context);

if (!result.allowed) {
  console.log("Prompt blocked:", result.issues);
}
```

## CLI Commands

The plugin supports these CLI commands when integrated with OpenClaw:

| Command | Description |
|---------|-------------|
| `openclaw upss validate-catalog` | Validate prompt catalog only |
| `openclaw upss dry-run` | Run validation without blocking |
| `openclaw upss report` | Output violations and risk stats |

## Error Handling

In strict mode, configuration errors will throw exceptions. In non-strict mode, warnings are logged and default values are used.

Default action when violations detected:
- `block`: Reject the prompt
- `sanitize`: Replace blocked patterns with `[REDACTED]`
- `warn_only`: Allow but log warnings

## Logging

Audit logs are written to:
- `~/.openclaw/upss/logs/upss_audit.jsonl` - Prompt access logs
- `~/.openclaw/upss/logs/agent_audit.jsonl` - Agent execution logs
