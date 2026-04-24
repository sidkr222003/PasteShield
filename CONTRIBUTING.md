# Contributing to PasteShield

Thank you for your interest in contributing! This document covers everything you need to get started.

---

## Table of Contents

- [Contributing to PasteShield](#contributing-to-pasteshield)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [Getting Started](#getting-started)
  - [Development Setup](#development-setup)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Running the Extension](#running-the-extension)
  - [Project Structure](#project-structure)
  - [Making Changes](#making-changes)
    - [Adding a Detection Pattern](#adding-a-detection-pattern)
    - [Coding Style](#coding-style)
    - [Commit Messages](#commit-messages)
  - [Submitting a Pull Request](#submitting-a-pull-request)
  - [Reporting Bugs](#reporting-bugs)
  - [Requesting Features](#requesting-features)
  
---

## Code of Conduct

Be respectful, constructive, and inclusive. Harassment or dismissive behaviour toward any contributor will not be tolerated.

---

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create a branch** for your change
4. **Make your changes** and test them
5. **Submit a pull request**

---

## Development Setup

### Prerequisites

- [Node.js](https://nodejs.org) v18 or later
- [VS Code](https://code.visualstudio.com) v1.93.0 or later
- npm (comes with Node.js)

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/pasteshield.git
cd pasteshield

# Install dev dependencies (~20 packages, no bloat)
npm install

# Compile TypeScript
npm run compile

# Or watch for changes during development
npm run watch
```

### Running the Extension

1. Open the project folder in VS Code
2. Press `F5` to launch the **Extension Development Host**
3. A new VS Code window opens with PasteShield loaded
4. Make changes in the main window — they hot-reload on recompile

---

## Project Structure

```
pasteshield/
├── src/
│   ├── features/
│   │   └── pasteShield/
│   │       ├── pasteShield.ts        # Command registration & paste interception
│   │       ├── pasteShieldConfig.ts  # Settings helpers
│   │       └── patternDetector.ts    # All detection patterns & severity logic
│   └── extension.ts                  # Extension entry point
├── resources/
│   └── icon.png                      # Extension icon (128×128 PNG)
├── .vscodeignore                      # Files excluded from the packaged .vsix
├── package.json
├── tsconfig.json
└── README.md
```

The core logic lives in `patternDetector.ts`. If you want to add a new detection pattern, that is the only file you need to touch.

---

## Making Changes

### Adding a Detection Pattern

Open `src/features/pasteShield/patternDetector.ts` and add an entry to the patterns array:

```typescript
{
  name: "My New Pattern",
  severity: "high",          // "critical" | "high" | "medium" | "low"
  pattern: /your-regex/gi,
  description: "Brief explanation of what this detects and why it is risky."
}
```

### Coding Style

- TypeScript strict mode is enabled — no `any` types
- Use `const` and `let`, never `var`
- Keep functions small and focused
- Add a JSDoc comment to any exported function

### Commit Messages

Use the format: `type: short description`

| Type | When to use |
|---|---|
| `feat` | New feature or detection pattern |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change with no behaviour change |
| `chore` | Build, config, or dependency updates |

Examples:
```
feat: add detection for hardcoded Stripe secret keys
fix: CodeLens annotations not clearing after ignore
docs: add examples to README configuration section
```

---

## Submitting a Pull Request

1. Ensure `npm run compile` passes with no errors
2. Test your change manually in the Extension Development Host
3. Update `README.md` if you added a new pattern or setting
4. Open a PR against the `main` branch
5. Fill in the PR template — describe what changed and why

Pull requests are reviewed within a few days. Please keep PRs focused on one thing; large mixed PRs are harder to review and slower to merge.

---

## Reporting Bugs

Open an issue at [github.com/sidkr222003/pasteshield/issues](https://github.com/sidkr222003/pasteshield/issues) and include:

- VS Code version (`Help → About`)
- PasteShield version (Extensions panel)
- Operating system
- Steps to reproduce
- What you expected vs. what happened

---

## Requesting Features

Open an issue with the label `enhancement`. Describe the use case — not just the solution — so we can find the best way to implement it.
