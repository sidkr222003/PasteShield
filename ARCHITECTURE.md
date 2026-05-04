# PasteShield Architecture & Function Reference

This document provides a detailed explanation of every major module, class, and function in PasteShield.

---

## Table of Contents

1. [Extension Entry Point](#extension-entry-point)
2. [Core Paste Interception](#core-paste-interception)
3. [Pattern Detection Engine](#pattern-detection-engine)
4. [Configuration System](#configuration-system)
5. [History Management](#history-management)
6. [History View Provider](#history-view-provider)
7. [Statistics Manager](#statistics-manager)
8. [Ignore Patterns Manager](#ignore-patterns-manager)
9. [Custom Patterns Manager](#custom-patterns-manager)
10. [Secret Management Integration](#secret-management-integration)
11. [Enterprise Policy Manager](#enterprise-policy-manager)
12. [Utilities](#utilities)

---

## Extension Entry Point

**File:** `src/extension.ts`

### `activate(context: vscode.ExtensionContext)`
- Called by VS Code when the extension loads
- Registers the main `registerPasteShield()` function
- Initializes **CustomPatternsManager**, **SecretManagementIntegration**, and **EnterprisePolicyManager**
- Registers four top-level commands:
  - `pasteShield.manageCustomPatterns` — Opens a QuickPick UI to add, edit, toggle, remove, or export custom regex patterns
  - `pasteShield.configureSecretManager` — Prompts the user to select a secret manager provider (Vault, AWS, Azure, GCP)
  - `pasteShield.listStoredSecrets` — Lists all secrets stored in the configured secret manager with rotate/delete actions
  - `pasteShield.showEnterprisePolicy` — Displays the active enterprise policy and compliance report
  - `pasteShield.exportComplianceReport` — Exports the enterprise compliance report as JSON

### `deactivate()`
- Empty cleanup hook for VS Code extension lifecycle

### Helper Functions in `extension.ts`
- `promptAddCustomPattern()` — Interactive wizard to create a new custom pattern (name, regex, severity, description, category)
- `promptEditCustomPattern()` — Wizard to modify an existing custom pattern
- `promptImportPatterns()` — File picker to import patterns from JSON
- `exportCustomPatterns()` — Save dialog to export custom patterns to JSON

---

## Core Paste Interception

**File:** `src/features/pasteShield/pasteShield.ts`

### `registerPasteShield(context: vscode.ExtensionContext)`
- Initializes all decoration types, CodeLens provider, managers, and the status bar
- Registers **all commands** and **event listeners**
- Sets up workspace watchers for `.pasteshieldignore` and `.gitignore`
- Key subsystems initialized here:
  - `HistoryManager` — Persistent scan history
  - `HistoryViewProvider` — Sidebar tree view
  - `StatisticsManager` — Analytics engine
  - `IgnorePatternsManager` — Workspace/user ignore lists

### `handlePaste()`
- The core paste interception handler bound to `pasteShield.paste`
- Flow:
  1. Checks if PasteShield is enabled via `getConfig()`
  2. Skips `.env` / `.env.local` files via `isPasteExcludedFile()`
  3. Skips ignored language IDs
  4. Reads clipboard via `vscode.env.clipboard.readText()`
  5. Runs `scanContent()` asynchronously via `runScanAsync()`
  6. Filters by minimum severity via `meetsSeverityThreshold()`
  7. If clean → calls `executeFallbackPaste()`
  8. If dirty → shows `showWarningMessage()` with "Paste Anyway / Show Details / Cancel"
  9. On "Paste Anyway" → `insertText()` + `applyDecoration()` + history entry
  10. On "Show Details" → `showDetailsPanel()` + modal re-confirmation
  11. On "Cancel" → logs cancellation + history entry

### `runScanAsync(text, options)`
- Wraps `scanContent()` in a `setTimeout(0)` microtask to avoid blocking the UI thread
- Logs a warning if scanning exceeds 50 ms

### `executeFallbackPaste()`
- Performs the actual paste when no threats are detected
- Handles both empty cursors (insert) and selections (replace)

### `insertText(editor, text)`
- Replaces selections or inserts at cursor positions using `editor.edit()`
- Returns the range of the first insertion for decoration purposes

### `buildSummaryMessage(detections)`
- Builds a human-readable warning string (e.g., "3 issues detected — AWS Key, GitHub Token +1 more")

### `showDetailsPanel(detections)`
- Opens a formatted plaintext report in a side panel (`ViewColumn.Beside`)
- Lists each detection with severity, type, category, line, description, and redacted match

### `addToIgnoredPatterns(patternName)`
- Appends a pattern name to the global `pasteShield.ignoredPatterns` setting

### `applyDecoration(editor, range, severity)`
- Adds a short-lived inline decoration at the paste insertion point
- Uses `ThemeColor` for light/dark theme support
- Auto-clears after 10 seconds

### `pruneStaleDecorations()`
- Removes decorations from editors that are no longer visible
- Debounced to 150 ms to avoid thrashing during rapid tab switching

### `updateStatusBar(enabled)`
- Renders `$(shield)` icon with theme-aware colors
- Green = active, Yellow = disabled
- Clicking toggles PasteShield on/off

### `togglePasteShield()`
- Flips the `pasteShield.enabled` boolean in global settings
- Refreshes status bar and CodeLens visibility
- Shows a progress notification for 2.5 seconds

### `exportHistory(format)`
- Exports history as JSON or plain text via a save dialog
- JSON uses `historyManager.exportAsJson()`
- Text uses `historyManager.exportAsText()`

### `showLastReport()`
- Re-opens the last scan report panel (if any)

### `showStatisticsDashboard()`
- Opens a formatted statistics report in a side panel
- Calls `statisticsManager.generateReport()`

### `exportAuditLog()`
- Exports a JSON audit log of all history entries with timestamps, files, actions, and detections
- Respects the `pasteShield.enableAuditLogging` setting

### `showRotationReminders()`
- Scans history for secrets older than `pasteShield.secretRotationReminderDays` (default 90)
- Groups by type/category and shows a sorted warning list
- Offers a "Rotate Now" button that links to GitHub secret rotation docs

### `PasteShieldCodeLensProvider`
- Implements `vscode.CodeLensProvider`
- `provideCodeLenses()` scans the full document text and creates three lenses per detection:
  1. Severity badge (e.g., "$(error) PasteShield [CRITICAL]: AWS Access Key ID")
  2. "$(info) View Details" → opens the security report
  3. "$(mute) Ignore Pattern" → adds pattern to ignored list
- `refresh()` fires `onDidChangeCodeLenses` to trigger re-rendering

---

## Pattern Detection Engine

**File:** `src/features/pasteShield/patternDetector.ts`

### `scanContent(text, options)`
- The main scanning function. Iterates over all `PATTERN_DEFINITIONS` (~200 patterns)
- Options:
  - `ignoredPatterns` — skips patterns by name
  - `maxResults` — caps results (default 50)
  - `categories` — filters to specific categories only
- Re-creates regexes from source to avoid `lastIndex` state bugs with `/g`
- Returns one `DetectionResult` per pattern (first match wins)
- Sorts results by severity: critical → high → medium → low

### `PATTERN_DEFINITIONS`
- Pre-compiled array of ~200 regex patterns across 25+ categories:
  - **AI Providers** — OpenAI, Anthropic, Gemini, xAI/Grok, DeepSeek, Mistral, Cohere, Hugging Face, Replicate, Together, Groq, Perplexity, ElevenLabs, OpenRouter, Azure OpenAI, LangSmith, Voyage, Fireworks, Cerebras, Stability, Fal.ai, Modal, Baseten
  - **AWS** — Access Key ID, Secret Key, Session Token, Account ID, ARN, S3 Pre-signed URL, CodeCommit, ECR
  - **Google Cloud** — Service Account JSON, OAuth Client Secret, Refresh Token, Firebase credentials, GCS Signed URL, Maps API
  - **Azure** — Subscription ID, Client Secret, Storage Key, SAS Token, Connection String, Service Bus, Cosmos DB, Event Hub, Tenant ID
  - **Source Control** — GitHub PAT (classic & fine-grained), OAuth, App, Refresh tokens; GitLab PAT, Trigger, Runner, Deploy tokens; Bitbucket App Password
  - **CI/CD** — CircleCI, Travis CI, Jenkins, Vercel, Netlify, Render, Railway, Fly.io, Heroku, Buildkite, Drone, Spacelift, Coolify
  - **Communication** — Slack Bot/User/App/Config tokens, Webhook; Discord Bot/Webhook; Telegram; Twilio; SendGrid; Mailchimp; Mailgun; Postmark; Resend; Teams Webhook; Vonage; Pusher; Plivo; Zulip
  - **Payments** — Stripe (live/test/publishable/webhook/restricted), PayPal, Razorpay, Braintree, Square, Adyen, Paddle, Mollie, Lemon Squeezy, Checkout.com
  - **Databases** — Generic connection strings, Supabase, PlanetScale, Neon, MongoDB Atlas, Turso, Upstash, Airtable, Pinecone, Weaviate, Qdrant, Xata, Fauna, CockroachDB, Convex
  - **Monitoring** — Datadog, Sentry, New Relic, Grafana, Logflare, Honeycomb, Axiom, Better Stack, Rollbar, Bugsnag
  - **Auth & Identity** — Auth0, Clerk, Okta, JWT, NextAuth, Better Auth, WorkOS, Stytch, Passage
  - **Crypto / Web3** — Ethereum private key, BIP39 mnemonic, Alchemy, Infura, QuickNode, Moralis, Helius
  - **Infrastructure** — Cloudflare, DigitalOcean, Linode/Akamai, Terraform Cloud, Vault, Doppler, Pulumi, Infisical, Cloudsmith, Fastly
  - **Package Registries** — npm, PyPI, RubyGems, JFrog Artifactory, Sonatype Nexus
  - **Social APIs** — Twitter/X, Facebook, Instagram, LinkedIn, Shopify, Figma, Notion, Linear, Intercom, HubSpot, Zendesk, Salesforce, Asana, Jira, Confluence, WooCommerce, Contentful, Sanity, Vercel Blob
  - **Keys & Certs** — PEM private keys, OpenSSH keys, PGP keys, certificates, PKCS12
  - **Generic Secrets** — Hardcoded passwords, API keys, Basic Auth URLs, `.env` contents, Docker registry creds, Authorization headers
  - **Unsafe Code** — `eval()`, `innerHTML`, `document.write`, React `dangerouslySetInnerHTML`, `setTimeout`/`setInterval` with strings, `Function` constructor, shell exec with user input, Python `subprocess(shell=True)`, `os.system()`, unsafe deserialization, prototype pollution, SQL injection, path traversal, SSRF, disabled TLS, hardcoded crypto keys, weak hashing, `Math.random()` for security, ReDoS, insecure Python random
  - **PII** — US SSN, credit cards, IBAN, Indian Aadhaar/PAN, UK NINO, Canadian SIN, passport numbers, internal RFC1918 IPs
  - **Mobile / IoT** — Apple APNs, Google FCM, Expo, AWS IoT, MQTT
  - **Search & Data** — Algolia, Typesense, Elastic, Meilisearch, Segment, Mixpanel, Amplitude, PostHog
  - **Storage & CDN** — Cloudinary, Bunny.net, Uploadthing, ImageKit, Backblaze B2, Wasabi
  - **Maps & Geo** — Mapbox, Google Maps, HERE, TomTom

### `getLineNumber(text, index)`
- Calculates 1-indexed line number for a regex match index

### `redactMatch(match)`
- Masks sensitive matches, preserving only first 4 and last 4 characters
- Used when `PatternDefinition.redact = true`

### `truncateMatch(match)`
- Truncates matches to 60 characters for safe display
- Used when `PatternDefinition.redact = false`

### `getCategories()`
- Returns all unique category strings in the pattern registry

---

## Configuration System

**File:** `src/features/pasteShield/pasteShieldConfig.ts`

### `getConfig(): PasteShieldConfig`
- Reads all PasteShield settings from VS Code workspace configuration in one call
- Returns typed object with defaults:
  - `enabled: true`
  - `ignoredPatterns: []`
  - `showInlineDecorations: true`
  - `minimumSeverity: 'medium'`
  - `ignoredLanguages: []`

### `meetsSeverityThreshold(detectedSeverity, threshold)`
- Compares severity levels using a numeric order map (`critical=0`, `high=1`, `medium=2`, `low=3`)
- Returns `true` if detected severity is at least as severe as the threshold

### `ALL_PATTERN_NAMES`
- Array of all built-in pattern names for settings IntelliSense

---

## History Management

**File:** `src/utils/historyManager.ts`

### `HistoryManager`
- Singleton using VS Code `globalState` for persistent storage
- Key: `pasteShield.scanHistory`
- Max entries: 100 (auto-trims old entries)

### `addEntry(entry)`
- Adds a scan entry with auto-generated ID and timestamp
- Respects the `pasteShield.enableHistory` setting
- Prepends to the list (most recent first)

### `getHistory()`
- Returns all stored `ScanHistoryEntry` objects

### `clearHistory()`
- Wipes all history from `globalState`

### `getStatistics()`
- Aggregates counts by severity, category, type, and action (pasted/cancelled/ignored)

### `exportAsJson()`
- Returns the full history array as a formatted JSON string

### `exportAsText()`
- Returns a human-readable plain text report with dates, files, actions, and detections

---

## History View Provider

**File:** `src/features/pasteShield/historyViewProvider.ts`

### `HistoryViewProvider`
- Implements `vscode.TreeDataProvider<HistoryItem>`
- Displays scan history in the VS Code sidebar under "PasteShield History"

### `getChildren(element?)`
- Root level: returns history entries or an empty-state message
- Entry level: returns detection items for that entry

### `createEntryItem(entry)`
- Formats each entry with:
  - Truncated file name (last 3 path segments)
  - Action icon (green check = pasted, red skip = cancelled, yellow eye = ignored)
  - Time, highest severity, and detection count in description

### `getSeverityThemeIcon(severity)`
- Maps severity to VS Code theme icons:
  - critical → `error` (red)
  - high → `stop` (orange)
  - medium → `warning` (blue)
  - low → `info` (gray)

### `getActionThemeIcon(action)`
- Maps action to colored theme icons using terminal ANSI colors

---

## Statistics Manager

**File:** `src/features/pasteShield/statisticsManager.ts`

### `StatisticsManager`
- Singleton that derives analytics from `HistoryManager`

### `getSummary()`
- Returns aggregated metrics:
  - total scans, total detections, threats blocked, pasted/cancelled/ignored counts
  - severity breakdown (critical/high/medium/low)
  - top 10 detected types and categories
  - average detections per scan

### `getDailyStats(days)`
- Returns per-day stats for the last N days (default 7)
- Includes scan count, detection count, pasted/cancelled counts, and severity breakdown per day

### `getWeeklyTrend(weeks)`
- Returns per-week stats for the last N weeks (default 4)
- Calculates a `threatLevel` ('low' | 'medium' | 'high' | 'critical') based on critical/high counts

### `getRiskScore()`
- Computes a 0-100 risk score based on the last 7 days
- Weights: critical=10, high=5, medium=2, low=1 (today gets 3x weight)

### `generateReport()`
- Builds a formatted ASCII dashboard report
- Includes overview, severity breakdown, risk score, top types, top categories, and 7-day bar chart

---

## Ignore Patterns Manager

**File:** `src/features/pasteShield/ignorePatternsManager.ts`

### `IgnorePatternsManager`
- Singleton that manages three sources of ignore rules:
  1. **User-level** — from `pasteShield.ignoredPatterns` setting
  2. **Workspace-level** — from `.pasteshieldignore` file in workspace root
  3. **Gitignore-derived** — relevant patterns from `.gitignore` (secret-related keywords)

### `loadWorkspacePatterns()`
- Parses `.pasteshieldignore` line-by-line, skipping comments and empty lines

### `loadGitignorePatterns()`
- Parses `.gitignore` and filters for secret-related keywords (`.env`, `secret`, `key`, `token`, etc.)

### `shouldIgnore(patternName, filePath?)`
- Checks all three sources for matches
- Supports exact match, glob match (`minimatch`), and substring match

### `addToWorkspaceIgnore(pattern)`
- Appends a pattern to `.pasteshieldignore` with a timestamp comment
- Creates the file if it doesn't exist

### `removeFromWorkspaceIgnore(pattern)`
- Removes a pattern line from `.pasteshieldignore`

### `refresh()`
- Reloads all patterns from disk (called on file changes)

---

## Custom Patterns Manager

**File:** `src/features/pasteShield/customPatternsManager.ts`

### `CustomPatternsManager`
- Singleton that stores user-defined regex patterns in VS Code settings under `pasteShield.customPatterns`

### `loadCustomPatterns()`
- Reads and compiles all enabled custom patterns from settings
- Invalid regexes are skipped with a warning

### `compilePatterns()`
- Converts `CustomPattern` objects into compiled `RegExp` instances
- Stores them in a `Map<string, CustomPatternDefinition>`

### `addPattern(pattern)`
- Validates regex before saving
- Prevents duplicate names
- Saves to global configuration

### `removePattern(name)`
- Removes a pattern by name from settings

### `togglePattern(name, enabled)`
- Flips the `enabled` flag on a pattern

### `editPattern(oldName, newPattern)`
- Replaces an existing pattern with a new one

### `importPatterns(jsonContent)`
- Parses a JSON array of patterns
- Validates each pattern has name, regex, severity
- Merges with existing patterns (updates duplicates by name)

### `exportPatterns()`
- Returns all custom patterns as a formatted JSON string

### `refresh()`
- Reloads patterns from settings

### `scanWithCustomPatterns(text, patterns)`
- Standalone scanner function for custom patterns
- Returns detections with the same shape as built-in patterns

---

## Secret Management Integration

**File:** `src/features/pasteShield/secretManagement.ts`

### `SecretManagementIntegration`
- Singleton that abstracts secret storage behind provider plugins

### Providers (all extend `SecretProvider`):
- **`VaultProvider`** — HashiCorp Vault (mock implementation using in-memory Map)
- **`AwsSecretsManagerProvider`** — AWS Secrets Manager (mock)
- **`AzureKeyVaultProvider`** — Azure Key Vault (mock)
- **`GoogleSecretManagerProvider`** — Google Secret Manager (mock)

### `loadConfiguration()`
- Reads all provider-specific settings (URLs, tokens, regions, project IDs) from `pasteShield.*` config keys

### `initializeProvider()`
- Instantiates the correct provider based on `secretManagerProvider` setting

### `storeDetectedSecret(secretValue, metadata)`
- Stores the detected secret via VS Code's built-in `SecretStorage` API (OS-level keychain)
- For external providers, credentials are loaded from SecretStorage and the secret is passed to the provider mock
- Generates a unique ID
- Returns the secret ID

### `getStoredSecret(id)`
- Retrieves a secret by ID from the configured provider or VS Code SecretStorage

### `deleteStoredSecret(id)`
- Removes a secret from the provider or VS Code SecretStorage

### `listStoredSecrets()`
- Returns all stored secrets (metadata only; values remain in SecretStorage)

### `rotateStoredSecret(id, newValue)`
- Updates a secret's value while preserving metadata

### `quickStoreAction(secretValue, metadata)`
- Prompts the user to store a detected secret immediately after detection
- If no external provider is configured, stores in VS Code SecretStorage (OS keychain)

### `init()`
- Loads sensitive provider credentials from VS Code `SecretStorage` (never from `settings.json`)
- Initializes the correct provider after credentials are available

### `storeCredential(key, value)`
- Stores a provider credential securely in VS Code `SecretStorage`
- Triggers provider re-initialization if already loaded

### `isConfigured()`
- Returns `true` if a provider other than `none` is selected in settings

---

## Enterprise Policy Manager

**File:** `src/features/pasteShield/enterprisePolicy.ts`

### `EnterprisePolicyManager`
- Singleton for team-wide security policy enforcement
- Loads policy from `.pasteshield-policy.json` (workspace-level) or extension storage

### `loadPolicy()`
- Reads the JSON policy file if it exists
- Falls back to a `getDefaultPolicy()` template

### `getDefaultPolicy()`
- Includes three starter rules:
  1. Block critical patterns (AWS keys, GitHub PATs, PEM keys)
  2. Audit-log all high-severity detections
  3. Warn on secrets older than 90 days

### `loadTeamMembers()`
- Reads `teamMembers` array from VS Code settings

### `checkPolicyViolation(detectionType, severity, category?, filePath?)`
- Evaluates a detection against all active policy rules
- Rule types:
  - `block_pattern` — blocks specific pattern names
  - `allowed_categories` — blocks categories not in the allowlist
  - severity-based blocking
- Supports exception lists (file patterns or user groups)
- Returns `{ violated, rule, action, message }`

### `applyPolicyAction(violation, detectionType)`
- Executes the policy action:
  - `block` → modal error message, returns `'blocked'`
  - `warn` → warning notification, returns `'warned'`
  - `audit` → console log, returns `'audited'`
  - `encrypt` → info message, returns `'audited'`

### `createPolicyFromTemplate(template)`
- Predefined templates: `strict` (block critical+high), `moderate` (block critical, warn high), `permissive` (audit only)

### `savePolicy()`
- Writes the current policy to `.pasteshield-policy.json`

### Policy File Schema
- Schema URL: `https://raw.githubusercontent.com/sidkr222003/pasteshield/main/schema/policy.schema.json`
- Local schema file: `schema/policy.schema.json`
- Example policy: `examples/pasteshield-policy.example.json`
- Add a `$schema` field to enable VS Code validation in-editor

```json
{
  "$schema": "https://raw.githubusercontent.com/sidkr222003/pasteshield/main/schema/policy.schema.json",
  "version": "1.0.0",
  "id": "default-policy",
  "name": "Default Security Policy",
  "description": "Standard security policy for all developers",
  "enabled": true,
  "rules": []
}
```

### Policy Field Reference

**Top-level fields**

| Field | Type | Required | Allowed values | Default |
|---|---|---|---|---|
| `$schema` | string | No | URL to JSON Schema | None (optional) |
| `version` | string | Yes | Any string (recommended SemVer) | None (required) |
| `id` | string | Yes | Any non-empty string | None (required) |
| `name` | string | Yes | Any non-empty string | None (required) |
| `description` | string | Yes | Any string | None (required) |
| `enabled` | boolean | Yes | `true` or `false` | None (required) |
| `enforcedAt` | number | No | Unix timestamp in ms | Not set |
| `rules` | array | Yes | Array of rule objects | None (required) |

**Rule fields**

| Field | Type | Required | Allowed values | Default |
|---|---|---|---|---|
| `id` | string | Yes | Any non-empty string | None (required) |
| `type` | string | Yes | `block_pattern`, `require_encryption`, `audit_logging`, `rotation_policy`, `allowed_categories` | None (required) |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low` | None (required) |
| `action` | string | Yes | `block`, `warn`, `audit`, `encrypt` | None (required) |
| `patternNames` | array | Conditionally | Array of pattern names | `[]` (required for `block_pattern`) |
| `categories` | array | Conditionally | Array of category names | `[]` (required for `allowed_categories`) |
| `message` | string | No | Any string | Not set |
| `exceptions` | array | No | Array of file patterns or group names | Not set |

### `generateComplianceReport(history)`
- Analyzes the last 30 days of scan history
- Computes:
  - Compliance score (0-100)
  - Total scans, violations, blocked pastes, warnings
  - Severity counts
  - Top violators and top detected types

### `exportComplianceReport(report)`
- Saves the compliance report as JSON via a save dialog

### `togglePolicy(enabled)`
- Enables/disables the active policy

### `addRule(rule)` / `removeRule(ruleId)`
- Mutates the policy rules array and saves

### `isEnterpriseModeEnabled()`
- Reads the `pasteShield.enterpriseMode` boolean setting

---

## Utilities

**File:** `src/utils/logger.ts`

### `createLogger(name)`
- Creates a VS Code OutputChannel logger
- Methods: `info()`, `warn()`, `error()`, `debug()`
- Formats payloads: strings pass through, Errors use `.stack`, objects use `JSON.stringify`

**File:** `src/utils/debounce.ts`

### `debounce(fn, wait)`
- Standard debounce utility using `NodeJS.Timeout`
- Used in PasteShield to throttle CodeLens refreshes and decoration pruning

---

## Command Reference

| Command ID | Handler Location | Description |
|---|---|---|
| `pasteShield.paste` | `pasteShield.ts` | Intercepted paste command (bound to Ctrl+V / Cmd+V) |
| `pasteShield.toggle` | `pasteShield.ts` | Toggle PasteShield on/off globally |
| `pasteShield.showLastReport` | `pasteShield.ts` | Open the last scan report panel |
| `pasteShield.codeLensDetails` | `pasteShield.ts` | Show detection details from CodeLens |
| `pasteShield.codeLensIgnore` | `pasteShield.ts` | Ignore pattern from CodeLens |
| `pasteShield.codeLensFix` | `pasteShield.ts` | Open settings to fix/rotate a credential |
| `pasteShield.showDetectionDetails` | `pasteShield.ts` | Show modal with detection type, severity, category |
| `pasteShield.showHistory` | `pasteShield.ts` | Focus the history sidebar view |
| `pasteShield.clearHistory` | `pasteShield.ts` | Clear all scan history (with confirmation) |
| `pasteShield.exportHistoryJson` | `pasteShield.ts` | Export history as JSON file |
| `pasteShield.exportHistoryText` | `pasteShield.ts` | Export history as plain text file |
| `pasteShield.refreshHistory` | `pasteShield.ts` | Refresh the history tree view |
| `pasteShield.showStatistics` | `pasteShield.ts` | Open the statistics dashboard |
| `pasteShield.exportAuditLog` | `pasteShield.ts` | Export audit log as JSON |
| `pasteShield.showRotationReminders` | `pasteShield.ts` | Show secrets needing rotation |
| `pasteShield.addToWorkspaceIgnore` | `pasteShield.ts` | Add a pattern to `.pasteshieldignore` |
| `pasteShield.manageCustomPatterns` | `extension.ts` | Open custom pattern management UI |
| `pasteShield.configureSecretManager` | `extension.ts` | Select and configure secret manager provider |
| `pasteShield.listStoredSecrets` | `extension.ts` | List, view, rotate, or delete stored secrets |
| `pasteShield.showEnterprisePolicy` | `extension.ts` | Display enterprise policy report |
| `pasteShield.exportComplianceReport` | `extension.ts` | Export compliance report as JSON |
| `pasteShield.validatePolicyFile` | `extension.ts` | Validate `.pasteshield-policy.json` and report errors |

---

## Settings Reference

| Setting | Type | Default | Description |
|---|---|---|---|
| `pasteShield.enabled` | `boolean` | `true` | Master on/off switch |
| `pasteShield.minimumSeverity` | `string` | `"medium"` | Minimum severity to trigger warning |
| `pasteShield.showInlineDecorations` | `boolean` | `true` | Show paste-point decorations |
| `pasteShield.showCodeLens` | `boolean` | `true` | Show CodeLens warnings in open files |
| `pasteShield.ignoredPatterns` | `string[]` | `[]` | Pattern names to skip |
| `pasteShield.ignoredLanguages` | `string[]` | `[]` | Language IDs to skip |
| `pasteShield.codeLensExcludedFiles` | `string[]` | `[]` | File basenames to exclude from CodeLens |
| `pasteShield.enableHistory` | `boolean` | `true` | Enable scan history tracking |
| `pasteShield.autoRefreshHistory` | `boolean` | `true` | Auto-refresh history sidebar on new scans |
| `pasteShield.customPatterns` | `object[]` | `[]` | User-defined regex patterns |
| `pasteShield.secretManagerProvider` | `string` | `"none"` | Provider: `none`, `vault`, `aws`, `azure`, `gcp`. Credentials stored via SecretStorage. |
| `pasteShield.vaultUrl` | `string` | — | HashiCorp Vault URL (non-sensitive) |
| `pasteShield.awsRegion` | `string` | — | AWS region (non-sensitive) |
| `pasteShield.azureVaultUrl` | `string` | — | Azure Key Vault URL (non-sensitive) |
| `pasteShield.gcpProjectId` | `string` | — | GCP project ID (non-sensitive) |
| `pasteShield.enterpriseMode` | `boolean` | `false` | Enable enterprise policy enforcement |
| `pasteShield.teamMembers` | `object[]` | `[]` | Team members for enterprise |
| `pasteShield.enableAuditLogging` | `boolean` | `true` | Enable audit log generation |
| `pasteShield.secretRotationReminderDays` | `number` | `90` | Days before rotation reminder |

---

## Data Flow Diagram

```
User Paste (Ctrl+V)
       │
       ▼
┌─────────────────┐
│  handlePaste()  │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
 .env file?  Disabled?
    │         │
    No        No
    │         │
    └────┬────┘
         ▼
  readClipboard()
         │
         ▼
  scanContent() ──► PatternDetector (100+ regexes)
         │
    ┌────┴────┐
    ▼         ▼
  Clean     Threats
    │         │
    ▼         ▼
 fallback   showWarningMessage()
   paste    /     │      \
            ▼     ▼       ▼
       Paste   Show    Cancel
       Anyway  Details
            │     │
            ▼     ▼
      insertText() re-prompt modal
      applyDecoration()  │
      history entry      ▼
                   insertText() or cancel
```

---

## Security Notes

- **Clipboard data never leaves the machine** — all scanning is local
- **History is stored in VS Code `globalState`** — cleared when VS Code is uninstalled
- **Secrets and provider credentials are stored via VS Code `SecretStorage`** — delegates to OS-level keychain (Windows Credential Manager, macOS Keychain, Linux libsecret). No custom encryption, no plaintext credentials in settings.
- **Audit logs are in-memory / exported manually** — no automatic remote transmission
- **`.env` files are excluded from paste interception** by design (secrets are intentional there)
- **CodeLens still runs on `.env` files** so existing secrets are visible


