<!--
Sync Impact Report (temporary; remove before commit)
- Version change: (unfilled template) → 1.0.0
- Modified principles: none renamed (initial ratification)
- Added principles: I. Focused Scope; II. Small, Explicit CLI; III. Secure Persistent Storage;
  IV. Secrets Never Leak; V. Isolated Credential Sessions; VI. Respect User Configuration;
  VII. Separated Responsibilities; VIII. Cross-Platform Support; IX. Security-Focused Testing;
  X. Honest Documentation; XI. Established Building Blocks
- Added sections: Platform & Security Constraints; Development Workflow
- Removed sections: none
- Source: principles adapted from nixos-contrib/nix-vault .specify/memory/constitution.md
- Deferred TODOs: none in text, but the project scope ("Cloudflare credentials delivered to
  commands") is an assumption from the repo name and sibling projects; confirm and amend if wrong.
-->
# cf-vault Constitution

## Core Principles

### I. Focused Scope
cf-vault MUST do one thing: securely obtain, store, and deliver Cloudflare credentials to the
commands that need them. Features that do not serve that purpose MUST be rejected or placed in
a separate project.
Rationale: a narrow product is easier to audit, which matters for security tooling.

### II. Small, Explicit CLI
The CLI surface MUST stay small, behavior MUST be explicit (no hidden side effects or implicit
state changes), and configuration MUST be minimal, with safe defaults. Every command MUST
document what it reads, writes, and executes. Errors go to stderr with a non-zero exit code;
output intended for scripts MUST be stable.

### III. Secure Persistent Storage (NON-NEGOTIABLE)
Persistent credentials MUST be stored using a secure platform facility (e.g. macOS Keychain,
Secret Service on Linux). If no secure store is available, cf-vault MUST fail with a clear
error and MUST NOT silently fall back to plaintext storage. Any insecure option MUST be an
explicit, opt-in user action that is clearly warned about.

### IV. Secrets Never Leak (NON-NEGOTIABLE)
Secrets MUST NOT appear in committed configuration, command-line arguments, logs, error
messages, or any other diagnostic output. Secrets MUST be passed via files with restrictive
permissions, stdin, or the environment of the target process only as necessary, and MUST be
redacted wherever they could be displayed.

### V. Isolated Credential Sessions
Credentials MUST be supplied to commands through isolated execution sessions scoped to the
command's lifetime. cf-vault MUST NOT permanently modify the user's shell or tool
configuration to deliver credentials, and session material MUST be cleaned up on exit.

### VI. Respect User Configuration
Unrelated user configuration MUST be preserved byte-for-byte where practical. When cf-vault
detects a conflict with existing configuration, it MUST report the conflict clearly and MUST
NOT overwrite or resolve it silently.

### VII. Separated Responsibilities
Authentication, credential storage, and credential delivery MUST be separate internal
components with explicit interfaces. Each MUST be testable independently, and none may depend
on the internals of another.

### VIII. Cross-Platform Support
cf-vault MUST support macOS and Linux. Platform-specific behavior MUST be isolated behind the
storage and delivery interfaces and covered by tests or documented verification steps.

### IX. Security-Focused Testing
Security-sensitive behavior (storage, redaction, cleanup, permissions, conflict handling) and
user-visible workflows MUST have automated tests. Tests MUST use fake credentials and mock
services only; real credentials MUST NOT be used in tests, fixtures, or CI.

### X. Honest Documentation
Documentation MUST state known limitations plainly, including at minimum: cleanup after
crashes or forced termination and credential renewal during long-running commands. Features
MUST NOT be described as providing guarantees they do not provide.

### XI. Established Building Blocks
Implementations MUST prefer established libraries and platform facilities over custom
cryptography or speculative infrastructure. Custom cryptographic code is prohibited. New
dependencies and abstractions MUST be justified by a present requirement, not a hypothetical
one.

## Platform & Security Constraints

- Supported targets: macOS and Linux; other platforms are out of scope until amended here.
- Credential files or sockets created at runtime MUST use owner-only permissions.
- Dependencies MUST be reviewed for security posture and maintenance before adoption.
- Real credentials, tokens, or private keys MUST NOT be committed anywhere in the repository.

## Development Workflow

- Every change MUST be reviewed against this constitution; security-sensitive changes require
  tests per Principle IX before merge.
- Any user-visible behavior change MUST update the documentation, including the limitations
  required by Principle X.
- Complexity that departs from Principles I, II, or XI MUST be justified in the plan or PR.

## Governance

This constitution supersedes other practices. Amendments MUST be made by a documented change
that states the rationale, updates the version, and describes any migration impact on existing
code or specs. Versioning follows semantic versioning: MAJOR for removals or redefinitions of
principles, MINOR for new or materially expanded principles or sections, PATCH for
clarifications. Compliance MUST be verified in plan reviews and pull request reviews, and
violations MUST be fixed or explicitly justified and recorded.

**Version**: 1.0.0 | **Ratified**: 2026-11-13 | **Last Amended**: 2026-11-13
