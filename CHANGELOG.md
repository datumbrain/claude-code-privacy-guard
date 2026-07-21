# Changelog

## v0.2.2 - 2026-07-22

- chore: remove npm publish step from release script
- feat: detect GitLab tokens and Azure client secrets
- feat: add Slack, GitLab, npm, Twilio, SendGrid, GCP SA, and DB connection-string detectors
- fix: merge overlapping findings and guard against empty-match regex hang
- fix: make the hook cross-platform by removing the bash wrapper
- test: add false-positive regression corpus


## v0.2.1 - 2026-07-22

- chore: stop committing source maps and make dist/ non-reviewed generated output


## v0.2.0 - 2026-07-20

- feat: add rule ID visibility, stable IDs, list_rules tool, and rules-picker CLI


## v0.1.9 - 2026-07-18

- docs: trim README PII claims to match actual detection
- docs: add CONTRIBUTING.md, issue templates, and README config reference
- fix: make debug logging opt-in and mask secrets in block messages
