# Claude Code Privacy Guard

<img src="./assets/claude-code-privacy-guard-logo.png" alt="Claude Code Privacy Guard Logo" align="right" height="80" />

> 🛡️ Prevent secrets and PII from being accidentally shared with Claude Code.

A privacy-first plugin for Claude Code that scans prompts for sensitive data and **blocks** them before they reach the AI.

## Features

- ✅ **Blocks prompts** containing sensitive data before they're sent to Claude
- ✅ **Detects** PII, secrets, API keys, tokens, and sensitive information
- ✅ **Works locally** - all scanning happens on your machine
- ✅ **Zero configuration** - works out of the box
- ✅ **Detailed reporting** - shows exactly what was detected

## Installation

```bash
# Add the marketplace (if not already added)
/plugin marketplace add datumbrain/claude-code-privacy-guard

# Install the plugin
/plugin install claude-code-privacy-guard
```

> **⚠️ Important: Restart Required**
>
> After installing the plugin, you must **restart your Claude Code session** for it to take effect. This is because hooks are registered at session startup - Claude Code doesn't dynamically load new hooks mid-session.
>
> Simply close and reopen Claude Code, or start a new session.

Once restarted, the plugin will automatically scan all prompts before they reach Claude.

## What Gets Detected

✅ **Secrets**
- OpenAI API keys (`sk-...`, `sk-proj-...`)
- AWS credentials
- GitHub tokens
- Stripe keys
- JWT tokens
- Bearer tokens
- SSH private keys
- Generic API key patterns

✅ **Personal Information (PII)**
- Email addresses
- Phone numbers
- Social Security Numbers
- Credit card numbers

## How It Works

1. You type a prompt in Claude Code
2. Privacy Guard intercepts it via a `UserPromptSubmit` hook
3. Scans for sensitive data using regex patterns
4. **Blocks the prompt** if sensitive data is found
5. Shows you exactly what was detected

Blocking relies on the `UserPromptSubmit` hook JSON protocol: the hook prints `{"decision": "block", "reason": "..."}` to stdout and exits with code `0`. (Exit code `0` is required for the JSON decision to be honored - a non-zero exit is treated as a non-blocking hook error, and the prompt would go through anyway.)

## Example

**Input:**
```
My API key is sk-proj-abc123xyz and email is john@example.com
```

**Result:**
```
🛡️ Privacy Guard blocked this prompt

Found 2 sensitive item(s):
  - API_KEY: sk-proj-abc123xyz...
  - EMAIL: john@example.com...

Risk Score: 100/100
Secrets: 1 | PII: 1

Please remove or anonymize sensitive data before proceeding.
```


## Configuration

Create a `.privacy-guard.json` file (searched upward from your current
working directory, so a repo-root or home-directory config both work) to
override the defaults. See `.privacy-guard.example.json` for a starter
file.

| Option | Type | Default | Status |
| --- | --- | --- | --- |
| `enabled` | `boolean` | `true` | ✅ Implemented. Set to `false` to disable the plugin entirely without uninstalling it. |
| `disabledRules` | `string[]` | `[]` | ✅ Implemented. Rule IDs to skip - see the built-in `id` fields in `src/scanner/detectors.ts` or the `name` fields in `data/regex_list_1.json` for external rules. |
| `externalRulesJsonPath` | `string` | `./data/regex_list_1.json` | ✅ Implemented. Path (relative to the config file's directory) to the external regex dataset. |
| `externalRulesMode` | `"coding-only" \| "all"` | `"coding-only"` | ✅ Implemented. `"coding-only"` filters the external dataset down to rules whose name/description mentions a coding-secret keyword (key, token, secret, password, private key, etc.); `"all"` loads every external rule. |
| `strictMode` | `boolean` | `false` | ⚠️ Accepted in config but not yet enforced by the scanner ([#6](https://github.com/datumbrain/claude-code-privacy-guard/issues/6)). |
| `allowedDomains` | `string[]` | `[]` | ⚠️ Accepted in config but not yet enforced by the scanner ([#6](https://github.com/datumbrain/claude-code-privacy-guard/issues/6)). |
| `redactionStyle` | `"placeholder" \| "mask" \| "remove"` | `"placeholder"` | ⚠️ Accepted in config but not yet enforced by the scanner ([#6](https://github.com/datumbrain/claude-code-privacy-guard/issues/6)). |
| `autoMaskOnHighRisk` | `boolean` | `true` | ⚠️ Accepted in config but not yet enforced by the scanner ([#6](https://github.com/datumbrain/claude-code-privacy-guard/issues/6)). |

Example:

```json
{
  "enabled": true,
  "disabledRules": [],
  "externalRulesJsonPath": "./data/regex_list_1.json",
  "externalRulesMode": "coding-only"
}
```

## Development

```bash
# Clone the repository
git clone https://github.com/datumbrain/claude-code-privacy-guard.git
cd claude-code-privacy-guard

# Install dependencies
npm install

# Build
npm run build

# Test the scanner directly
echo "test sk-proj-abc123" | node scripts/prompt-guard.js
```

Release:
```bash
make release
```
This runs an interactive flow that asks for version bump, confirms release actions, updates `CHANGELOG.md`, runs build/test, creates commit+tag, and optionally pushes/publishes.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to add a detection rule and the `dist/` rebuild requirement, and [docs/](./docs/) for detailed architecture and integration guides.

## Privacy & Security

- ✅ All scanning happens **locally on your machine**
- ✅ No data is sent to external services
- ✅ No telemetry or tracking
- ✅ Open source and fully auditable
- ✅ The plugin only blocks - it doesn't store or log your sensitive data

## Why Block Instead of Redact?

Claude Code's hook system doesn't support transforming prompts - only blocking or adding context. Blocking ensures sensitive data **never** reaches the AI, which is the safest approach.

## Debugging

Check the debug log if you encounter issues:

```bash
cat /tmp/claude-code-privacy-guard.log
```

## Contributing

Contributions welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, how to add a detection rule, and the release process.

## License

MIT © Datum Brain
