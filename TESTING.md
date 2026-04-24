# PasteShield Testing Guide

This document covers how to test PasteShield features manually and describes the current test coverage.

---

## Manual Testing Checklist

### Core Paste Interception

| Test Case | Steps | Expected Result |
|---|---|---|
| Basic paste with no secrets | Copy plain text, press `Ctrl+V` / `Cmd+V` | Text pastes immediately without any warning |
| Paste with API key | Copy `sk-abcdefghijklmnopqrstuvwxyz123456`, paste into a JS file | Warning dialog appears with severity, pattern name, and match |
| Paste with multiple secrets | Copy text containing both AWS key and GitHub token | Warning shows summary of multiple issues |
| Paste Anyway | In warning dialog, click "Paste Anyway" | Text is inserted, inline decoration appears for 10s |
| Show Details | In warning dialog, click "Show Details" | Side panel opens with full security report |
| Cancel paste | In warning dialog, click "Cancel" or dismiss | Nothing is pasted; entry added to history as cancelled |
| Paste into .env file | Copy an API key, paste into `.env` | Pastes silently without interception (by design) |
| Paste into ignored language | Set `pasteShield.ignoredLanguages` to `["markdown"]`, paste secret in `.md` | Pastes silently |
| Toggle off | Run command "PasteShield: Toggle On/Off", paste secret | Pastes silently without scanning |
| Toggle on | Run command "PasteShield: Toggle On/Off" again, paste secret | Warning dialog appears |

### CodeLens Warnings

| Test Case | Steps | Expected Result |
|---|---|---|
| Open file with secrets | Open a file containing hardcoded passwords | CodeLens annotations appear above risky lines |
| Severity badge lens | Hover over the first lens | Shows severity and pattern name |
| View Details lens | Click "$(info) View Details" | Side panel opens with detection details |
| Ignore Pattern lens | Click "$(mute) Ignore Pattern" | Pattern is added to `ignoredPatterns`; lens disappears |
| Toggle off CodeLens | Set `pasteShield.showCodeLens: false` | All lenses disappear |
| Re-enable CodeLens | Set `pasteShield.showCodeLens: true` | Lenses reappear after file change or save |
| Disable PasteShield | Toggle PasteShield off | All lenses disappear globally |

### Inline Decorations

| Test Case | Steps | Expected Result |
|---|---|---|
| Decoration on warn paste | Click "Paste Anyway" for a detected secret | Inline decoration appears at paste point |
| Decoration theme | Switch between light and dark themes | Decoration colors adapt to theme |
| Decoration auto-clear | Wait 10 seconds after "Paste Anyway" | Decoration disappears automatically |
| Decoration disabled | Set `pasteShield.showInlineDecorations: false` | No decoration appears |

### History & Sidebar

| Test Case | Steps | Expected Result |
|---|---|---|
| History entry created | Paste a secret and choose any action | Entry appears in "PasteShield History" sidebar |
| History details | Expand a history entry | Detection items appear with severity icons |
| Show detection details | Click a detection in history | Modal shows type, severity, and category |
| Clear history | Run "PasteShield: Clear History" | Confirm modal appears; history is emptied |
| Export JSON | Run "PasteShield: Export History as JSON" | Save dialog opens; valid JSON is written |
| Export text | Run "PasteShield: Export History as Text" | Save dialog opens; human-readable report is written |
| Refresh history | Run "PasteShield: Refresh History" | Tree view refreshes |
| Auto-refresh | Paste a new secret with `autoRefreshHistory: true` | Sidebar updates automatically |

### Statistics Dashboard

| Test Case | Steps | Expected Result |
|---|---|---|
| Show statistics | Run "PasteShield: Show Statistics" | Side panel opens with ASCII dashboard |
| Daily stats | Paste multiple secrets over several days | 7-day bar chart shows per-day detection counts |
| Risk score | Review the dashboard | Risk score (0-100) reflects recent activity |
| Top types | Dashboard shows top detected types | Matches actual history |
| Top categories | Dashboard shows top categories | Matches actual history |

### Custom Patterns

| Test Case | Steps | Expected Result |
|---|---|---|
| Add custom pattern | Run "PasteShield: Manage Custom Patterns" → "Add Pattern" | Pattern is saved and scanning uses it |
| Custom pattern detection | Paste text matching custom regex | Warning shows the custom pattern name |
| Edit pattern | Select pattern → "Edit" | Updated pattern is saved |
| Toggle pattern | Select pattern → "Toggle Enable/Disable" | Pattern is skipped when disabled |
| Remove pattern | Select pattern → "Remove" | Pattern is deleted |
| Import patterns | Select "Import Patterns" → pick JSON file | Patterns are merged into settings |
| Export patterns | Select "Export" → save JSON file | Valid JSON with all patterns is saved |
| Invalid regex | Enter invalid regex when adding | Error message shown; pattern not saved |
| Duplicate name | Add pattern with existing name | Warning shown; pattern not added |

### Secret Management

| Test Case | Steps | Expected Result |
|---|---|---|
| Configure provider | Run "PasteShield: Configure Secret Manager" → select Vault/AWS/Azure/GCP | Provider setting is updated |
| Store secret | After detection, choose "Store" in quick-store prompt | Secret is encrypted and stored; ID returned |
| List secrets | Run "PasteShield: List Stored Secrets" | QuickPick shows all stored secrets |
| View details | Select a secret → "View Details" | Modal shows metadata (type, detected date, stored date) |
| Rotate secret | Select a secret → "Rotate" → enter new value | Secret value is updated |
| Delete secret | Select a secret → "Delete" → confirm | Secret is removed |
| Not configured warning | List secrets without configuration | Warning offers to configure |

### Enterprise Policy

| Test Case | Steps | Expected Result |
|---|---|---|
| Enable enterprise mode | Set `pasteShield.enterpriseMode: true` | Policy enforcement becomes active |
| Show policy | Run "PasteShield: Show Enterprise Policy" | Side panel shows policy rules and compliance |
| Block rule | Paste a secret matching a `block` rule | Modal error prevents paste |
| Warn rule | Paste a secret matching a `warn` rule | Warning notification appears; paste allowed |
| Audit rule | Paste a secret matching an `audit` rule | Console log entry created |
| Export compliance | Run "PasteShield: Export Compliance Report" | JSON report saved with 30-day metrics |
| Policy templates | Create strict/moderate/permissive policy | Rules reflect the template |
| Exceptions | Add file path to rule exceptions | Paste in that file bypasses the rule |

### Ignore Patterns

| Test Case | Steps | Expected Result |
|---|---|---|
| User ignore | Add pattern name to `pasteShield.ignoredPatterns` | That pattern is skipped in all scans |
| Workspace ignore | Run "PasteShield: Add to Workspace Ignore" → enter pattern | `.pasteshieldignore` is created/updated |
| Gitignore integration | Add `.env` to `.gitignore` | `.env` files are respected by ignore logic |
| Refresh patterns | Modify `.pasteshieldignore` while VS Code is open | Changes take effect on next scan (auto-refresh via file watcher) |

### Audit Logging

| Test Case | Steps | Expected Result |
|---|---|---|
| Export audit log | Run "PasteShield: Export Audit Log" | JSON file with all scan entries and detections |
| Audit disabled | Set `enableAuditLogging: false` | Export command shows warning |

### Rotation Reminders

| Test Case | Steps | Expected Result |
|---|---|---|
| Show reminders | Run "PasteShield: Show Rotation Reminders" | Lists secrets older than 90 days |
| No old secrets | With fresh history | Shows "All secrets rotated recently" message |
| Rotate button | Click "Rotate Now" in reminder modal | Opens GitHub secret rotation docs in browser |
| Custom reminder days | Set `secretRotationReminderDays: 30` | Reminders trigger at 30 days |

---

## Configuration Testing

| Setting | Test Value | Expected Behavior |
|---|---|---|
| `minimumSeverity` | `"critical"` | Only critical patterns trigger warnings |
| `minimumSeverity` | `"low"` | All severities trigger warnings |
| `ignoredLanguages` | `["plaintext"]` | Paste in `.txt` files is not scanned |
| `codeLensExcludedFiles` | `["config.ts"]` | CodeLens does not appear in `config.ts` |
| `showInlineDecorations` | `false` | No paste-point decorations |
| `showCodeLens` | `false` | No CodeLens annotations |
| `enableHistory` | `false` | No history entries are created |
| `autoRefreshHistory` | `false` | Sidebar does not auto-update |

---

## Edge Cases

| Scenario | Expected Behavior |
|---|---|
| Empty clipboard | Falls back to normal paste |
| Read-only document | Shows error: "document may be read-only" |
| Very large clipboard (> 5 KB) | Scan may exceed 50 ms; warning logged to output channel |
| No active editor | Falls back silently |
| Clipboard read failure | Logs error; falls back to normal paste |
| Malformed custom pattern JSON on import | Shows error; no patterns imported |
| `.pasteshieldignore` with invalid lines | Skips empty/comment lines; processes valid lines |
| Missing `.pasteshield-policy.json` | Loads default policy automatically |

---

## Automated Testing (Future)

While PasteShield currently relies on manual/integration testing, the following unit test categories are recommended:

### Pattern Detector Tests
- Each regex should match its intended input and not match benign input
- `redactMatch()` should mask middle characters
- `truncateMatch()` should cap at 60 characters
- `scanContent()` should respect `ignoredPatterns`, `maxResults`, and `categories`
- `getLineNumber()` should return correct 1-indexed line numbers

### Configuration Tests
- `getConfig()` should return correct defaults when settings are empty
- `meetsSeverityThreshold()` should handle all severity combinations correctly

### History Manager Tests
- `addEntry()` should prepend and trim to 100 entries
- `getStatistics()` should aggregate counts correctly
- `exportAsJson()` should produce valid JSON
- `exportAsText()` should include all entries in chronological order

### Statistics Manager Tests
- `getSummary()` should calculate averages and top-N correctly
- `getDailyStats()` should bucket entries by calendar day
- `getRiskScore()` should be 0 for empty history and ≤ 100 for active history
- `generateReport()` should include all sections

### Ignore Patterns Tests
- `shouldIgnore()` should match exact names, globs, and substrings
- `isRelevantGitignorePattern()` should filter for secret-related keywords

### Enterprise Policy Tests
- `checkPolicyViolation()` should respect exceptions, pattern names, categories, and severities
- `generateComplianceReport()` should handle empty history gracefully (score = 100)

### Secret Management Tests
- `encryptSecret()` / `decryptSecret()` should be symmetrical
- `generateSecretId()` should produce unique IDs
- Provider mocks should store/retrieve/delete correctly

---

## Performance Benchmarks

| Metric | Target | Notes |
|---|---|---|
| Scan time for 1 KB text | < 10 ms | Typical clipboard size |
| Scan time for 5 KB text | < 50 ms | Warns if exceeded |
| CodeLens refresh | < 100 ms for 500-line files | Debounced to 500 ms |
| History sidebar refresh | < 50 ms | Instant for < 100 entries |
| Statistics report generation | < 20 ms | In-memory aggregation |

---

## Reporting Issues

When filing a bug, include:
1. VS Code version and PasteShield version
2. Minimal reproduction steps
3. Clipboard content (redacted) or pattern name
4. File type (language ID) and file name
5. Relevant settings from `settings.json`
6. Output channel logs (View → Output → "PasteShield")

