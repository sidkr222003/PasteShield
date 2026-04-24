# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.x (latest) | ✅ Yes |
| < 1.0 | ❌ No |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in PasteShield, report it privately by emailing the maintainer directly or using [GitHub's private vulnerability reporting](https://github.com/sidkr222003/pasteshield/security/advisories/new).

Include:

- A clear description of the vulnerability
- Steps to reproduce it
- The potential impact
- Any suggested fix (optional but appreciated)

You can expect an acknowledgement within **48 hours** and a resolution or status update within **7 days**.

## Scope

The following are in scope for security reports:

- False negatives — dangerous patterns that PasteShield fails to detect
- Bypass techniques — ways to paste malicious content without triggering a warning
- Extension security — vulnerabilities in PasteShield's own code

The following are **out of scope**:

- Vulnerabilities in VS Code itself — report those to [Microsoft](https://github.com/microsoft/vscode/security)
- Patterns that are low-risk by design (use the `minimumSeverity` setting to control these)

## Privacy Note

PasteShield processes clipboard content **entirely locally**. No clipboard data is ever transmitted to any external server. If you believe this guarantee is violated by any version of this extension, that is a critical security issue and should be reported immediately.
