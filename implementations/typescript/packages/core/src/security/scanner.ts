/**
 * Security utilities for UPSS.
 */

import * as crypto from "crypto";

// Dangerous patterns for injection detection
export const BLOCKLIST_PATTERNS: RegExp[] = [
  // Role confusion
  /you\s+are\s+now/i,
  /act\s+as/i,
  /pretend\s+to\s+be/i,
  // Instruction override
  /ignore\s+previous/i,
  /disregard\s+above/i,
  /new\s+instructions/i,
  // Delimiter injection
  /###/,
  /```/,
  /<\|endoftext\|>/i,
];

// PII patterns
export const PII_PATTERNS: Record<string, RegExp> = {
  email: /[\w.-]+@[\w.-]+\.\w+/,
  phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/,
  credit_card: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
};

/**
 * Sanitize user input to prevent injection attacks.
 * 
 * @param userInput - Raw user input string
 * @returns Tuple of (sanitized_string, is_safe_flag)
 */
export function sanitize(userInput: string): [string, boolean] {
  let isSafe = true;
  let sanitized = userInput;

  // Escape special characters
  const specialChars: Record<string, string> = {
    '"': "&quot;",
    "'": "&#x27;",
    '{': "&#123;",
    '}': "&#125;",
    '<': "&lt;",
    '>': "&gt;",
  };

  for (const [char, escape] of Object.entries(specialChars)) {
    sanitized = sanitized.split(char).join(escape);
  }

  // Check for injection patterns
  for (const pattern of BLOCKLIST_PATTERNS) {
    if (pattern.test(userInput)) {
      console.warn(`Injection pattern detected: ${pattern}`);
      isSafe = false;
    }
  }

  return [sanitized, isSafe];
}

/**
 * Render a prompt with user input using clear boundaries.
 * 
 * @param systemPrompt - The system prompt content
 * @param userInput - User input to be rendered
 * @param style - Rendering style ("xml" or "markdown")
 * @param allowUnsafe - Skip sanitization if True
 * @returns Rendered prompt with safe user input boundaries
 */
export function render(
  systemPrompt: string,
  userInput: string,
  style: "xml" | "markdown" = "xml",
  allowUnsafe = false
): string {
  // Sanitize unless explicitly allowed
  if (!allowUnsafe) {
    const [sanitized, isSafe] = sanitize(userInput);
    if (!isSafe) {
      console.warn("Unsafe patterns detected in user input during render");
      userInput = sanitized;
    }
  }

  if (style === "xml") {
    return `${systemPrompt}\n\n<user_input>${userInput}</user_input>`;
  } else if (style === "markdown") {
    return `${systemPrompt}\n\n### USER INPUT\n${userInput}\n### END USER INPUT`;
  } else {
    throw new Error(`Unknown style: ${style}`);
  }
}

/**
 * Calculate risk score (0-100) based on dangerous patterns.
 * 
 * @param content - Content to analyze
 * @returns Risk score from 0 to 100
 */
export function calculateRiskScore(content: string): number {
  let score = 0;
  let matches = 0;

  for (const pattern of BLOCKLIST_PATTERNS) {
    if (pattern.test(content)) {
      matches++;
    }
  }

  // Each match adds ~14 points
  score = Math.min(matches * 14, 100);
  return score;
}

/**
 * Detect PII in content.
 * 
 * @param content - Content to scan
 * @param block - Raise ComplianceError if PII found
 * @returns List of detected PII types
 * @throws Error if block=true and PII found
 */
export function detectPii(
  content: string,
  block = false
): string[] {
  const detected: string[] = [];

  for (const [piiType, pattern] of Object.entries(PII_PATTERNS)) {
    if (pattern.test(content)) {
      detected.push(piiType);
    }
  }

  if (block && detected.length > 0) {
    throw new Error(`PII detected: ${detected.join(", ")}`);
  }

  return detected;
}

/**
 * Compute SHA-256 checksum of content.
 * 
 * @param content - Content to hash
 * @returns Hex-encoded SHA-256 hash
 */
export function computeChecksum(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

/**
 * Verify checksum matches expected value.
 * 
 * @param content - Content to verify
 * @param expectedChecksum - Expected SHA-256 hash
 * @returns True if checksum matches
 */
export function verifyChecksum(content: string, expectedChecksum: string): boolean {
  const actual = computeChecksum(content);
  return actual === expectedChecksum;
}
