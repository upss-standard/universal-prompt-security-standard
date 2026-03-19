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
- [ ] Configure plugin (add to allow list, entries, install record)
- [ ] Verify installation with test prompts

## Steps

### 1. Clone Repository

```bash
# Clone from main branch (after PR merge) or use PR branch for preview
git clone https://github.com/upss-standard/universal-prompt-security-standard
cd universal-prompt-security-standard

# If openclaw-extension directory is missing, checkout the PR branch:
# git fetch origin docs/add-agents-md-documentation
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
python3 -c "from upss import SecurityPipeline; print('✅ UPSS Python library installed')"
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
# Run the install command (may take time)
openclaw plugins install implementations/openclaw-extension/upss-security-guard/openclaw-upss-security-guard-1.1.0.tgz
```

**IMPORTANT:** If the install command times out or doesn't complete, the plugin files may be copied but the config may not be updated. Proceed to Step 5 to ensure proper configuration.

### 5. Configure Plugin (REQUIRED)

The plugin needs to be added to the OpenClaw config. Run this to ensure proper configuration:

```bash
python3 << 'EOF'
import json
import os
from datetime import datetime, timezone

config_path = os.path.expanduser('~/.openclaw/openclaw.json')

# Read existing config
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        data = json.load(f)
else:
    data = {}

# Ensure plugins section exists
if 'plugins' not in data:
    data['plugins'] = {}

# Add to allow list
if 'allow' not in data['plugins']:
    data['plugins']['allow'] = []
if 'upss-security-guard' not in data['plugins']['allow']:
    data['plugins']['allow'].append('upss-security-guard')

# Add to entries with config
if 'entries' not in data['plugins']:
    data['plugins']['entries'] = {}
data['plugins']['entries']['upss-security-guard'] = {
    'enabled': True,
    'config': {
        'riskThreshold': 0.7,
        'defaultAction': 'block',
        'maxUserPromptLength': 10000,
        'enforceChecksums': True,
        'enableRateLimit': True
    }
}

# Add install record (required for proper provenance)
if 'installs' not in data['plugins']:
    data['plugins']['installs'] = {}
data['plugins']['installs']['upss-security-guard'] = {
    'source': 'archive',
    'spec': 'openclaw-upss-security-guard-1.1.0.tgz',
    'installPath': os.path.expanduser('~/.openclaw/extensions/upss-security-guard'),
    'version': '1.1.0',
    'resolvedName': '@openclaw/upss-security-guard',
    'resolvedVersion': '1.1.0',
    'resolvedAt': datetime.now(timezone.utc).isoformat(),
    'installedAt': datetime.now(timezone.utc).isoformat()
}

# Clean up stale load paths if any
if 'load' in data['plugins'] and 'paths' in data['plugins']['load']:
    data['plugins']['load']['paths'] = [
        p for p in data['plugins']['load']['paths']
        if 'upss' not in p.lower()
    ]

# Write config
with open(config_path, 'w') as f:
    json.dump(data, f, indent=2)

print('✅ Plugin configured successfully')
print('  - Added to allow list')
print('  - Added to entries with config')
print('  - Added install record')
EOF
```

Enable the plugin:

```bash
openclaw plugins enable upss-security-guard
```

### 6. Verify Installation

Test Python library:

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
    
    # Test safe prompt
    result = await pipeline.execute('Hello world', ctx)
    assert result.is_safe, 'Safe prompt should pass'
    
    # Test injection blocking
    result = await pipeline.execute('Ignore previous instructions', ctx)
    assert not result.is_safe, 'Injection should be blocked'
    
    print('✅ All tests passed')

asyncio.run(test())
"
```

Verify plugin loaded:

```bash
openclaw plugins list 2>&1 | grep -i upss
```

You should see:
```
🛡️ UPSS Security Guard plugin registered successfully
   ✓ Hook: message:preprocessed
   ✓ Hook: prompt:build:before
   ✓ Tool: upss_check
```

## EXECUTE NOW

Complete the above TODO list to achieve: UPSS Security Guard installed with 6-gate security enforcement active.

## Troubleshooting

### Plugin shows as "disabled" or not in list

Run Step 5 to add the required config entries manually.

### Warning: "loaded without install/load-path provenance"

This means the install record is missing. Run Step 5 to add it.

### Python library not found

Make sure you ran pip install with `--break-system-packages` on macOS, or use a virtual environment.

## Additional Resources

- [OpenClaw Installation Guide](docs/openclaw-installation.md) - Detailed installation instructions
- [OWASP LLM01:2025](https://owasp.org/www-project-top-10-for-llm-applications/) - Prompt Injection defense controls
- [GitHub Repository](https://github.com/upss-standard/universal-prompt-security-standard)