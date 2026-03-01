#!/usr/bin/env bash
# UPSS Security Guard — Bootstrap Installer
# Universal Prompt Security Standard (UPSS) v1.1.0+
# Author: Alvin T. Veroy | OWASP LLM01:2025 Aligned

set -euo pipefail

VERSION="1.1.0"
INSTALL_DIR="${UPSS_INSTALL_DIR:-$HOME/.upss}"
SKILL_DIR="${OPENCLAW_SKILL_DIR:-$HOME/.openclaw/skills/upss-security-guard}"
DB_FILE="$INSTALL_DIR/upss.db"
KEY_DIR="$INSTALL_DIR/keys"
LOG_DIR="$INSTALL_DIR/logs"
AUDIT_LOG="$LOG_DIR/audit.log"

echo "🛡️  UPSS Security Guard Installer v$VERSION"
echo "═══════════════════════════════════════════════"
echo ""

# Check dependencies
command -v openssl >/dev/null 2>&1 || { echo "❌ Error: openssl not found. Install it first."; exit 1; }
command -v sqlite3 >/dev/null 2>&1 || { echo "❌ Error: sqlite3 not found. Install it first."; exit 1; }

echo "✅ Dependencies check passed (openssl, sqlite3)"
echo ""

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p "$INSTALL_DIR" "$KEY_DIR" "$LOG_DIR" "$SKILL_DIR"
echo "   → $INSTALL_DIR"
echo "   → $KEY_DIR"
echo "   → $LOG_DIR"
echo "   → $SKILL_DIR"
echo ""

# Initialize SQLite RBAC database
echo "🗄️  Initializing SQLite RBAC database..."
sqlite3 "$DB_FILE" <<'SQL'
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  rate_limit INTEGER NOT NULL DEFAULT 60,
  created_at INTEGER DEFAULT (strftime('%s', 'now')),
  last_active INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER DEFAULT (strftime('%s', 'now')),
  user_id TEXT NOT NULL,
  gate_id TEXT NOT NULL,
  control_id TEXT NOT NULL,
  action TEXT NOT NULL,
  matched_pattern TEXT,
  prompt_hash TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS rate_limit_state (
  user_id TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, window_start),
  FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS prompt_checksums (
  file_path TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  algorithm TEXT DEFAULT 'sha256',
  verified_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_rate_limit ON rate_limit_state(user_id, window_start);

-- Insert default admin user
INSERT OR IGNORE INTO users (user_id, username, role, rate_limit)
VALUES ('admin', 'admin', 'admin', 1000);

-- Insert default user
INSERT OR IGNORE INTO users (user_id, username, role, rate_limit)
VALUES ('default', 'default', 'user', 60);
SQL

echo "   ✅ Database initialized at $DB_FILE"
echo "   ✅ Created tables: users, audit_log, rate_limit_state, prompt_checksums"
echo "   ✅ Default users: admin (1000 req/min), default (60 req/min)"
echo ""

# Generate master signing key using OpenSSL
echo "🔐 Generating OpenSSL master signing key..."
openssl genpkey -algorithm RSA -out "$KEY_DIR/master.key" -pkeyopt rsa_keygen_bits:4096 2>/dev/null
openssl rsa -pubout -in "$KEY_DIR/master.key" -out "$KEY_DIR/master.pub" 2>/dev/null
chmod 600 "$KEY_DIR/master.key"
chmod 644 "$KEY_DIR/master.pub"
echo "   ✅ Private key: $KEY_DIR/master.key (4096-bit RSA)"
echo "   ✅ Public key: $KEY_DIR/master.pub"
echo ""

# Copy SKILL.md to OpenClaw skill directory
if [ -f "SKILL.md" ]; then
  echo "📋 Installing SKILL.md to OpenClaw..."
  cp SKILL.md "$SKILL_DIR/SKILL.md"
  echo "   ✅ Installed: $SKILL_DIR/SKILL.md"
  echo ""
fi

# Create symlinks for CLI tools
echo "🔗 Creating CLI symlinks..."
for script in upss-rbac.sh upss-guard.sh upss-keygen.sh upss-audit.sh; do
  if [ -f "scripts/$script" ]; then
    ln -sf "$(pwd)/scripts/$script" "$INSTALL_DIR/${script%.sh}"
    chmod +x "scripts/$script"
  fi
done
echo "   ✅ Symlinked: upss-rbac, upss-guard, upss-keygen, upss-audit"
echo ""

# Add to PATH suggestion
echo "📌 Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Add to your shell PATH:"
echo "     export PATH=\"\$PATH:$INSTALL_DIR\""
echo ""
echo "  2. Verify installation:"
echo "     upss-guard --version"
echo ""
echo "  3. Create users:"
echo "     upss-rbac add-user <username> --role user|developer|admin"
echo ""
echo "  4. Test a prompt:"
echo "     upss-guard check 'Hello world'"
echo ""
echo "  5. View audit logs:"
echo "     upss-audit --tail 20"
echo ""
echo "═══════════════════════════════════════════════"
echo "🛡️  UPSS v$VERSION | https://github.com/upss-standard/universal-prompt-security-standard"
