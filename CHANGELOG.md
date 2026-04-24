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

<!-- 
Template for future releases:

## [X.Y.Z] — YYYY-MM-DD

### Added
- 

### Changed
- 

### Fixed
- 

### Removed
- 
-->
