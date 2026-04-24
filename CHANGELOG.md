# Changelog

All notable changes to PasteShield are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-04-24

### Added

- Real-time paste interception via `Ctrl+V` / `Cmd+V` keybinding override
- Detection patterns across four severity levels: `critical`, `high`, `medium`, `low`
- Warning dialog with severity label, pattern name, and proceed/cancel options
- Inline CodeLens annotations above risky lines in open files
- Gutter decoration at paste insertion point (auto-clears after 10 seconds)
- **PasteShield: Show Last Scan Report** command for full paste breakdown
- **PasteShield: Toggle On/Off** command and editor context menu entry
- `minimumSeverity` setting to filter warning noise
- `ignoredPatterns` setting to suppress specific pattern names
- `ignoredLanguages` setting to disable scanning per language ID
- `codeLensExcludedFiles` setting to exclude files from CodeLens scanning
- Automatic exclusion of `.env` and `.env.local` files from paste interception
- Fully offline — no clipboard data ever leaves the machine

---

## v1.6.0 — Pattern Expansion (COMPLETED)

- [x] Add detection for AWS, GCP, and Azure credential patterns
- [x] Add detection for Slack, Stripe, and GitHub tokens
- [x] Add detection for SSH private key blocks
- [x] Add detection for hardcoded connection strings (MongoDB, PostgreSQL, MySQL)
- [x] Expanded coverage: AI providers (OpenAI, Anthropic, Gemini, Groq, etc.)
- [x] Expanded coverage: CI/CD platforms (Vercel, Netlify, Railway, Fly.io)
- [x] Expanded coverage: Communication (Discord, Telegram, Twilio, SendGrid)
- [x] Expanded coverage: Payments (Stripe, PayPal, Razorpay, Square, Adyen)
- [x] Expanded coverage: Databases (Supabase, PlanetScale, Neon, Turso, Upstash)
- [x] Unsafe code patterns: eval, innerHTML, prototype pollution, SQL injection, SSRF
- [x] PII detection: SSN, credit cards, IBAN, Aadhaar, PAN, UK NINO
- [x] Status bar item showing PasteShield enabled/disabled state
- [x] "Always allow this pattern" quick action from the warning dialog (via CodeLens ignore)
- [x] Inline paste-point decorations with theme-aware colors
- [x] Debounced CodeLens refresh and decoration pruning for performance
- [x] Persistent scan history across sessions with VS Code globalState storage
- [x] Export scan report as JSON or plain text
- [x] Sidebar history view with GitHub-style codeicons
- [x] Real-time history updates when keys are pasted anywhere
- [x] Enhanced visual hierarchy with severity-based icons and colors
- [x] Command registration for all history-related actions:
  - `pasteShield.refreshHistory` — Refresh the history view
  - `pasteShield.clearHistory` — Clear all scan history
  - `pasteShield.exportHistoryJson` — Export history as JSON file
  - `pasteShield.exportHistoryText` — Export history as plain text file
  - `pasteShield.showDetectionDetails` — Show details for individual detections
- [x] Improved empty state with helpful messaging
- [x] Configuration options for history tracking:
  - `pasteShield.enableHistory` — Enable/disable history tracking (default: true)
  - `pasteShield.autoRefreshHistory` — Auto-refresh on new scans (default: true)
- [x] Integration with secret management tools (Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager)
- [x] Store, retrieve, rotate, list, and delete detected secrets
- [x] Quick-store action prompted after detection
- [x] Secret rotation reminders for detected credentials
- [x] Team-wide policy enforcement for enterprise deployments
- [x] Centralized policy via `.pasteshield-policy.json`
- [x] Policy rule types: block_pattern, require_encryption, audit_logging, rotation_policy, allowed_categories
- [x] Strict / moderate / permissive policy templates
- [x] Compliance report generation (30-day metrics, score 0-100)
- [x] Audit log export for compliance reporting
- [x] Team member management with roles (admin, developer, auditor)
- [x] Custom user-defined patterns via settings (regex + severity)
- [x] Workspace-level ignore list separate from user-level (`.pasteshieldignore`)
- [x] Integration with `.gitignore`-style pattern files
- [x] Pattern management UI: add, edit, toggle, remove, import, export
- [x] Invalid regex validation with user-friendly error messages
- [x] File system watchers for `.pasteshieldignore` and `.gitignore` auto-refresh
- [x] Fixed the Run When it was not working properly

---

## [1.7.0] — 2026-05-15

### Added

- Expanded pattern coverage to **~200 patterns across 25+ categories**:
  - New categories: Mobile / IoT, Search & Data, Storage & CDN, Maps & Geo
  - New AI providers: xAI/Grok, DeepSeek, Together AI, Voyage, Fireworks, Cerebras, Fal.ai, Modal, Baseten
  - New infrastructure: Infisical, Cloudsmith, Fastly
  - New databases: Weaviate, Qdrant, Xata, Fauna, CockroachDB, Convex
  - New monitoring: Honeycomb, Axiom, Better Stack, Rollbar, Bugsnag
  - New auth: WorkOS, Stytch, Passage by 1Password
  - New crypto: Moralis, Helius
  - New social APIs: LinkedIn, Intercom, HubSpot, Zendesk, Salesforce, Asana, Jira, Confluence, WooCommerce, Contentful, Sanity, Vercel Blob
  - New package registries: JFrog Artifactory, Sonatype Nexus
  - Enhanced PII: Canadian SIN, passport numbers

### Security

- **Migrated all provider credentials to VS Code SecretStorage** (OS-level keychain). AWS keys, Azure secrets, Vault tokens, and GCP credentials are no longer stored in `settings.json`. They are collected via secure password prompts and stored in the OS keychain (Windows Credential Manager, macOS Keychain, Linux libsecret).
- Removed plaintext credential fields from extension manifest (`package.json`).

### Changed

- Fixed marketplace category to `Other` only (removed `Programming Languages`, `Machine Learning`, `Data Science`, `Debuggers`).
- Added `linter` keyword for better discoverability.
- Updated all documentation to reflect ~200 patterns / 25+ categories and SecretStorage architecture.

### Fixed

- Reduced package size and optimized code.
