# Milestones

Planned features and improvements for future releases.

---

## v1.1.0 — Pattern Expansion

- [ ] Add detection for AWS, GCP, and Azure credential patterns
- [ ] Add detection for Slack, Stripe, and GitHub tokens
- [ ] Add detection for SSH private key blocks
- [ ] Add detection for hardcoded connection strings (MongoDB, PostgreSQL, MySQL)

---

## v1.2.0 — UX Improvements

- [ ] Status bar item showing PasteShield enabled/disabled state
- [ ] Notification sound option for critical-severity detections
- [ ] Configurable warning dialog timeout (auto-dismiss after N seconds)
- [ ] "Always allow this pattern" quick action from the warning dialog

---

## v1.3.0 — Reporting

- [ ] Persistent scan history across sessions (opt-in)
- [ ] Export scan report as JSON or plain text
- [ ] Aggregate statistics panel (total pastes scanned, warnings triggered)

---

## Backlog (unscheduled)

- [ ] Custom user-defined patterns via settings (regex + severity)
- [ ] Workspace-level ignore list separate from user-level
- [ ] Integration with `.gitignore`-style pattern files
- [ ] Multi-root workspace support improvements
