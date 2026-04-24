# Milestones

Planned features and improvements for future releases.

---

## v1.5.0 — Custom Patterns & Ignore Management (COMPLETED)

- [x] Custom user-defined patterns via settings (regex + severity)
- [x] Workspace-level ignore list separate from user-level (`.pasteshieldignore`)
- [x] Integration with `.gitignore`-style pattern files
- [x] Pattern management UI: add, edit, toggle, remove, import, export
- [x] Invalid regex validation with user-friendly error messages
- [x] File system watchers for `.pasteshieldignore` and `.gitignore` auto-refresh
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
- [x] Status bar item showing PasteShield enabled/disabled state
- [x] "Always allow this pattern" quick action from the warning dialog (via CodeLens ignore)
- [x] Inline paste-point decorations with theme-aware colors
- [x] Debounced CodeLens refresh and decoration pruning for performance
- [ ] Notification sound option for critical-severity detections
- [ ] Configurable warning dialog timeout (auto-dismiss after N seconds)

---

## v1.1.0 — Pattern Expansion (COMPLETED)

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

---

## Backlog (unscheduled)

- [ ] Notification sound option for critical-severity detections
- [ ] Configurable warning dialog timeout (auto-dismiss after N seconds)
- [ ] Multi-root workspace support improvements
- [ ] Real-time team sync for enterprise policies via shared config repository
- [ ] Automatic secret rotation via provider APIs (AWS RotateSecret, Vault dynamic credentials)
- [ ] Machine learning-based false-positive reduction
- [ ] IDE-agnostic CLI version of PasteShield for CI/CD pipelines
- [ ] SARIF output format for integration with GitHub Advanced Security
- [ ] Baseline mode (ignore existing secrets in repo, flag only new ones)
- [ ] Integration with 1Password / Bitwarden secret references
- [ ] Offline mode with fully local encryption (no external secret manager)
- [ ] Custom severity override per workspace
- [ ] Pattern marketplace / community pattern sharing


