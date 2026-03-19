# UPSS TypeScript Implementations

TypeScript/Node.js implementations of the Universal Prompt Security Standard (UPSS).

## Packages

### @upss/core

Core security engine providing:

- `SecurityPipeline` - Composable middleware pipeline
- `SecurityMiddleware` - Base class for security checks
- `BasicSanitizer` - Injection pattern detection
- `InputValidator` - Encoding and length validation
- `SimpleRBAC` - Role-based access control

```bash
cd packages/core
npm install
npm run build
```

### @upss/openclaw

OpenClaw plugin providing:

- Hook implementations (`message:preprocessed`, `before_prompt_build`, `agent_end`)
- `upss_validate_prompt` tool for explicit validation
- Configuration-driven policy enforcement

```bash
cd packages/openclaw
npm install
npm run build
```

## Building

```bash
# Build all packages
npm run build

# Build specific package
npm run build -w @upss/core
npm run build -w @upss/openclaw
```

## Testing

```bash
npm run test
```

## Examples

See `examples/openclaw-basic/` for a complete working example.
