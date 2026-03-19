/**
 * Exception classes for UPSS.
 */

export class UPSSError extends Error {
  public readonly message: string;
  public readonly details: Record<string, unknown>;
  public readonly cause: Error | undefined;

  constructor(
    message: string,
    details: Record<string, unknown> = {},
    cause?: Error
  ) {
    super(message);
    this.message = message;
    this.details = details;
    this.cause = cause;
    this.name = "UPSSError";
  }
}

export class ConfigurationError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "ConfigurationError";
  }
}

export class StorageError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "StorageError";
  }
}

export class IntegrityError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "IntegrityError";
  }
}

export class PermissionError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "PermissionError";
  }
}

export class NotFoundError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "NotFoundError";
  }
}

export class ConflictError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "ConflictError";
  }
}

export class ComplianceError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "ComplianceError";
  }
}

export class SecurityError extends UPSSError {
  constructor(message: string, details?: Record<string, unknown>, cause?: Error) {
    super(message, details, cause);
    this.name = "SecurityError";
  }
}
