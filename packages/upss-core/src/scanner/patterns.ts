/**
 * Regex patterns for injection and PII detection.
 */

export const BLOCKLIST_PATTERNS = [
  // Role confusion
  /you\s+are\s+now/gi,
  /act\s+as/gi,
  /pretend\s+to\s+be/gi,
  // Instruction override
  /ignore\s+previous/gi,
  /disregard\s+above/gi,
  /new\s+instructions/gi,
  // Delimiter injection
  /###/g,
  /```/g,
  /<\|endoftext\|>/gi,
];

export const PII_PATTERNS: Record<string, RegExp> = {
  email: /[\w.-]+@[\w.-]+\.\w+/g,
  phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  credit_card: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
};

// Default injection patterns to block (from BasicSanitizer)
export const DEFAULT_INJECTION_PATTERNS = [
  // Instruction override
  /ignore\s+(previous|above|prior)\s+(instructions?|prompts?|commands?)/gi,
  /disregard\s+(previous|above|all|everything)/gi,
  /forget\s+(previous|above|all|everything)/gi,
  // Role confusion
  /you\s+are\s+now/gi,
  /act\s+as\s+if/gi,
  /pretend\s+(to\s+be|you\s+are)/gi,
  /simulate\s+(being|that\s+you)/gi,
  // System prompt injection
  /new\s+instructions:?/gi,
  /system\s*:\s*/gi,
  /<\s*\|\s*im_start\s*\|\s*>/gi,
  /<\s*\|\s*im_end\s*\|\s*>/gi,
  // Delimiter injection
  /---\s*end\s+of\s+prompt/gi,
  /```\s*system/gi,
  // Privilege escalation
  /sudo\s+mode/gi,
  /admin\s+mode/gi,
  /developer\s+mode/gi,
  /god\s+mode/gi,
  /root\s+access/gi,
];

// Control characters to check (except tab, newline, carriage return)
export const CONTROL_CHARS = Array.from({ length: 32 }, (_, i) => i)
  .filter((i) => i !== 9 && i !== 10 && i !== 13)
  .map((i) => String.fromCharCode(i));

export const SPECIAL_CHARS_ESCAPE: Record<string, string> = {
  '"': '\"',
  "'": "\'",
  '{': '\{',
  '}': '\}',
  '<': '\<',
  '>': '\>',
};
