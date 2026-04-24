# Milestones

Planned features and improvements for future releases.

---

## v1.3.0 — Reporting & History (COMPLETED)

- [x] Persistent scan history across sessions with VS Code globalState storage
- [x] Export scan report as JSON or plain text
- [x] Sidebar history view with GitHub-style codeicons
- [x] Real-time history updates when keys are pasted anywhere
- [x] Enhanced visual hierarchy with severity-based icons and colors
- [x] Command registration for all history-related actions:
  - `pasteShield.refreshHistory` - Refresh the history view
  - `pasteShield.clearHistory` - Clear all scan history
  - `pasteShield.exportHistoryJson` - Export history as JSON file
  - `pasteShield.exportHistoryText` - Export history as plain text file
  - `pasteShield.showDetectionDetails` - Show details for individual detections
- [x] Improved empty state with helpful messaging
- [x] Configuration options for history tracking:
  - `pasteShield.enableHistory` - Enable/disable history tracking (default: true)
  - `pasteShield.autoRefreshHistory` - Auto-refresh on new scans (default: true)

---

## v1.2.0 — UX Improvements (COMPLETED)

- [x] Status bar item showing PasteShield enabled/disabled state
- [ ] Notification sound option for critical-severity detections
- [ ] Configurable warning dialog timeout (auto-dismiss after N seconds)
- [x] "Always allow this pattern" quick action from the warning dialog

---

## v1.1.0 — Pattern Expansion (COMPLETED)

- [x] Add detection for AWS, GCP, and Azure credential patterns
- [x] Add detection for Slack, Stripe, and GitHub tokens
- [ ] Add detection for SSH private key blocks
- [x] Add detection for hardcoded connection strings (MongoDB, PostgreSQL, MySQL)

---

## Backlog (unscheduled)

- [ ] Custom user-defined patterns via settings (regex + severity)
- [ ] Workspace-level ignore list separate from user-level
- [ ] Integration with `.gitignore`-style pattern files
- [ ] Multi-root workspace support improvements
- [ ] Statistics dashboard showing total scans, threats blocked, and trends
- [ ] Secret rotation reminders for detected credentials
- [ ] Integration with secret management tools (Vault, AWS Secrets Manager)
- [ ] Team-wide policy enforcement for enterprise deployments
- [ ] Audit log export for compliance reporting
