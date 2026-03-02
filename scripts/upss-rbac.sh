#!/usr/bin/env bash
# UPSS Security Guard — RBAC Management CLI
# Universal Prompt Security Standard (UPSS) v1.1.0+
# Author: Alvin T. Veroy

set -euo pipefail

DB_FILE="${UPSS_INSTALL_DIR:-$HOME/.upss}/upss.db"

usage() {
  cat <<EOF
🛡️  UPSS RBAC Management CLI

Usage: upss-rbac <command> [options]

Commands:
  add-user <username> --role <role> [--rate-limit <N>]
      Create a new user with specified role
      Roles: user (default), developer, admin
      Rate limits: user=60, developer=100, admin=1000 req/min

  update-user <username> --role <role> | --rate-limit <N>
      Update an existing user's role or rate limit

  delete-user <username>
      Remove a user from the system

  list-users [--role <role>]
      List all users or filter by role

  show-user <username>
      Show detailed info for a specific user

  reset-rate-limit <username>
      Clear rate limit state for a user

Examples:
  upss-rbac add-user alice --role developer
  upss-rbac update-user bob --rate-limit 200
  upss-rbac list-users --role admin
  upss-rbac delete-user charlie
EOF
  exit 1
}

if [ ! -f "$DB_FILE" ]; then
  echo "❌ Error: Database not found at $DB_FILE"
  echo "Run 'upss-init.sh' first to initialize UPSS."
  exit 1
fi

command="${1:-}"
shift || true

case "$command" in
  add-user)
    username="${1:-}"
    shift || true
    role="user"
    rate_limit=""
    
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --role) role="$2"; shift 2 ;;
        --rate-limit) rate_limit="$2"; shift 2 ;;
        *) echo "❌ Unknown option: $1"; usage ;;
      esac
    done
    
    if [ -z "$username" ]; then
      echo "❌ Error: username required"
      usage
    fi
    
    if [ -z "$rate_limit" ]; then
      case "$role" in
        user) rate_limit=60 ;;
        developer) rate_limit=100 ;;
        admin) rate_limit=1000 ;;
        *) echo "❌ Invalid role: $role"; exit 1 ;;
      esac
    fi
    
    user_id=$(echo -n "$username" | sha256sum | cut -d' ' -f1 | head -c 16)
    
    sqlite3 "$DB_FILE" <<SQL
INSERT INTO users (user_id, username, role, rate_limit)
VALUES ('$user_id', '$username', '$role', $rate_limit);
SQL
    
    echo "✅ User created:"
    echo "   Username: $username"
    echo "   User ID: $user_id"
    echo "   Role: $role"
    echo "   Rate limit: $rate_limit req/min"
    ;;
    
  update-user)
    username="${1:-}"
    shift || true
    role=""
    rate_limit=""
    
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --role) role="$2"; shift 2 ;;
        --rate-limit) rate_limit="$2"; shift 2 ;;
        *) echo "❌ Unknown option: $1"; usage ;;
      esac
    done
    
    if [ -z "$username" ]; then
      echo "❌ Error: username required"
      usage
    fi
    
    if [ -n "$role" ]; then
      sqlite3 "$DB_FILE" "UPDATE users SET role='$role' WHERE username='$username';"
      echo "✅ Updated role to: $role"
    fi
    
    if [ -n "$rate_limit" ]; then
      sqlite3 "$DB_FILE" "UPDATE users SET rate_limit=$rate_limit WHERE username='$username';"
      echo "✅ Updated rate limit to: $rate_limit req/min"
    fi
    ;;
    
  delete-user)
    username="${1:-}"
    if [ -z "$username" ]; then
      echo "❌ Error: username required"
      usage
    fi
    
    sqlite3 "$DB_FILE" "DELETE FROM users WHERE username='$username';"
    echo "✅ User deleted: $username"
    ;;
    
  list-users)
    role_filter=""
    if [ "${1:-}" = "--role" ]; then
      role_filter="WHERE role='${2:-}'"
    fi
    
    echo "📄 UPSS Users:"
    echo ""
    sqlite3 "$DB_FILE" <<SQL
.mode column
.headers on
SELECT username, role, rate_limit, datetime(created_at, 'unixepoch') as created_at
FROM users $role_filter
ORDER BY created_at DESC;
SQL
    ;;
    
  show-user)
    username="${1:-}"
    if [ -z "$username" ]; then
      echo "❌ Error: username required"
      usage
    fi
    
    echo "👤 User Details: $username"
    echo ""
    sqlite3 "$DB_FILE" <<SQL
.mode line
SELECT 
  username,
  user_id,
  role,
  rate_limit,
  datetime(created_at, 'unixepoch') as created_at,
  datetime(last_active, 'unixepoch') as last_active
FROM users WHERE username='$username';
SQL
    
    echo ""
    echo "Recent audit events:"
    sqlite3 "$DB_FILE" <<SQL
.mode column
.headers on
SELECT 
  datetime(timestamp, 'unixepoch') as timestamp,
  gate_id,
  action,
  risk_level
FROM audit_log
WHERE user_id = (SELECT user_id FROM users WHERE username='$username')
ORDER BY timestamp DESC
LIMIT 10;
SQL
    ;;
    
  reset-rate-limit)
    username="${1:-}"
    if [ -z "$username" ]; then
      echo "❌ Error: username required"
      usage
    fi
    
    user_id=$(sqlite3 "$DB_FILE" "SELECT user_id FROM users WHERE username='$username';")
    if [ -z "$user_id" ]; then
      echo "❌ User not found: $username"
      exit 1
    fi
    
    sqlite3 "$DB_FILE" "DELETE FROM rate_limit_state WHERE user_id='$user_id';"
    echo "✅ Rate limit state cleared for: $username"
    ;;
    
  *)
    usage
    ;;
esac
