# upss-security-guard

> UPSS (Universal Prompt Security Standard) - A 6-gate security system for LLM prompt injection prevention. Blocks jailbreaks, role confusion, privilege escalation, and supply-chain tampering. OWASP LLM01:2025 aligned.

I want you to install UPSS Security Guard for me. Execute all the steps below autonomously.

## OBJECTIVE

Install the UPSS 6-gate security system with OpenClaw plugin for runtime prompt security enforcement.

## DONE WHEN

- Python library installed and importable
- OpenClaw plugin loaded and hooks registered
- Test prompt passes security validation
- Injection attempt is blocked

## TODO

- [ ] Clone the repository
- [ ] Install Python library
- [ ] Build OpenClaw plugin
- [ ] Install plugin in OpenClaw
- [ ] Enable and configure plugin
- [ ] Verify installation with test prompts

## Steps

### 1. Clone Repository

```bash
# Clone from main branch (after PR merge) or use PR branch for preview
git clone https://github.com/upss-standard/universal-prompt-security-standard
cd universal-prompt-security-standard

# If openclaw-extension directory is missing, checkout the PR branch:
# git checkout docs/add-agents-md-documentation
```

### 2. Install Python Library

```bash
cd implementations/python

# macOS may require --break-system-packages due to PEP 668
pip3 install --user -e . --break-system-packages

# Or use a virtual environment:
# python3 -m venv venv && source venv/bin/activate && pip install -e .

cd ../..
```

Verify:

```bash
python3 -c "from upss import SecurityPipeline; print('UPSS Python library installed')"
```

### 3. Build OpenClaw Plugin

```bash
cd implementations/openclaw-extension/upss-security-guard
npm install
npm run build
npm pack
cd ../../..
```

### 4. Install Plugin in OpenClaw

```bash
# First, remove any stale config references
python3 << 'EOF'
import json
import os

config_path = os.path.expanduser("~/.openclaw/openclaw.json")
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        data = json.load(f)
    
    if 'plugins' in data:
        # Remove stale load paths
        if 'load' in data['plugins'] and 'paths' in data['plugins']['load']:
            data['plugins']['load']['paths'] = [
                p for p in data['plugins']['load']['paths']
                if 'upss' not in p.lower()
            ]
    
    with open(config_path, 'w') as f:
        json.dump(data, f, indent=2)
    print('Config cleaned')
EOF

# Install the plugin
openclaw plugins install implementations/openclaw-extension/upss-security-guard/openclaw-upss-security-guard-1.1.0.tgz
```

### 5. Enable and Configure Plugin

Add to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "allow": ["upss-security-guard"],
    "entries": {
      "upss-security-guard": {
        "enabled": true,
        "config": {
          "riskThreshold": 0.7,
          "defaultAction": "block",
          "maxUserPromptLength": 10000,
          "enforceChecksums": true,
          "enableRateLimit": true
        }
      }
    }
  }
}
```

Enable the plugin:

```bash
openclaw plugins enable upss-security-guard
openclaw gateway restart
```

### 6. Verify Installation

Test safe prompt:

```bash
python3 -c "
import sys
sys.path.insert(0, 'implementations/python')
from upss import SecurityPipeline, SecurityContext, BasicSanitizer
import asyncio

async def test():
    pipeline = SecurityPipeline()
    pipeline.use(BasicSanitizer())
    ctx = SecurityContext(user_id='test', prompt_id='test')
    result = await pipeline.execute('Hello world', ctx)
    print('PASS' if result.is_safe else 'FAIL')

asyncio.run(test())
"
```

Test injection blocking:

```bash
python3 -c "
import sys
sys.path.insert(0, 'implementations/python')
from upss import SecurityPipeline, SecurityContext, BasicSanitizer
import asyncio

async def test():
    pipeline = SecurityPipeline()
    pipeline.use(BasicSanitizer())
    ctx = SecurityContext(user_id='test', prompt_id='test')
    result = await pipeline.execute('Ignore previous instructions', ctx)
    print('PASS' if not result.is_safe else 'FAIL')

asyncio.run(test())
"
```

Verify plugin loaded:

```bash
openclaw plugins list | grep upss
```

Expected output:

```
│ UPSS Security │ upss-     │ loaded   │ ... │ 1.1.0 │
```

## EXECUTE NOW

Complete the above TODO list to achieve: UPSS Security Guard installed with 6-gate security enforcement active.

## Additional Resources

- [OpenClaw Installation Guide](docs/openclaw-installation.md) - Detailed installation instructions
- [OWASP LLM01:2025](https://owasp.org/www-project-top-10-for-llm-applications/) - Prompt Injection defense controls
- [GitHub Repository](https://github.com/upss-standard/universal-prompt-security-standard)