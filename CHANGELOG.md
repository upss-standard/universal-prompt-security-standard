# Changelog

All notable changes to the Universal Prompt Security Standard (UPSS) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.1] - 2026-04-02

### Release Notes
## What's Changed
* feat(openclaw): update security guard plugin with full 6-gate implementation by @alvinveroy in https://github.com/upss-standard/universal-prompt-security-standard/pull/29


**Full Changelog**: https://github.com/upss-standard/universal-prompt-security-standard/compare/v1.3.0...v1.3.1
## [1.1.0] - 2025-11-08

### Added
- **Modular Middleware Architecture** - New composable security primitives
  - `SecurityPipeline`: Composable middleware pipeline for security checks
  - `SecurityContext`: Context information for security operations
  - `SecurityResult`: Result of security processing with violations and risk scores
  - `SecurityMiddleware`: Base class for creating custom security primitives
  
- **Essential Security Primitives**
  - `BasicSanitizer`: Block common prompt injection patterns (ignore previous, role confusion, system injection)
  - `LightweightAuditor`: File-based audit logging in JSONL format with query interface
  - `SimpleRBAC`: Role-based access control with configurable role mappings
  - `InputValidator`: Runtime input validation (null bytes, control chars, encoding, length limits)

- **Documentation**
  - `MIDDLEWARE.md`: Comprehensive guide for the new middleware architecture
  - `basic_middleware_usage.py`: Example demonstrating middleware composition
  - Complete test suite for all middleware components

- **Python Implementation Updates**
  - Updated `upss/__init__.py` to export middleware components
  - Maintained backward compatibility with v1.0 `UPSSClient`
  - Added fluent interface for pipeline composition

### Changed
- Version bumped to 1.1.0 (still in draft proposal phase)
- Updated author attribution to Alvin T. Veroy
- Enhanced package documentation with middleware examples

### Technical Details
- All middleware is async-first for high performance
- Middleware executes sequentially and stops on first failure
- Risk scores aggregate across middleware (0.0 = safe, 1.0 = maximum risk)
- Audit logs use JSONL format for easy parsing and querying
- Custom middleware can be created by extending `SecurityMiddleware`

### Migration Notes
- v1.0 `UPSSClient` remains fully supported
- New middleware architecture is opt-in
- Can be used alongside existing v1.0 code
- See `MIDDLEWARE.md` for migration examples

## [1.0.1] - 2025-10-29

### Release Notes
## What's Changed
* feat(ci): auto-update version in README, CITATION, and CHANGELOG on release by @alvinveroy in https://github.com/upss-standard/universal-prompt-security-standard/pull/17


**Full Changelog**: https://github.com/upss-standard/universal-prompt-security-standard/compare/v1.0.0...v1.0.1
### Added
- Initial draft of the Universal Prompt Security Standard (UPSS)

[1.0.1]: https://github.com/upss-standard/universal-prompt-security-standard/releases/tag/v1.0.1

[1.3.1]: https://github.com/upss-standard/universal-prompt-security-standard/releases/tag/v1.3.1
