# Contributing to Claude Code Privacy Guard

Thanks for considering a contribution. This project is intentionally small
and focused - most contributions fall into one of: a new detection rule, a
bug fix, or documentation.

## Dev setup

```bash
git clone https://github.com/datumbrain/claude-code-privacy-guard.git
cd claude-code-privacy-guard
npm install
npm run build
npm test
```

To try the hook directly without a full Claude Code session:

```bash
echo "my api key is sk-proj-abc123xyz1234567890" | node scripts/prompt-guard.js
```

## Adding a detection rule

Built-in rules live in `src/scanner/detectors.ts`, in the `BUILTIN_RULES`
array. Each rule is a `DetectionRule` (see `src/types/findings.ts`) with an
`id`, `title`, `description`, `severity`, `category` (`secret` or `pii`), a
`pattern` regex, a `redactionStrategy`, and `examples`.

1. Add the rule to `BUILTIN_RULES`.
2. Add tests in `tests/rules.test.ts`:
   - a **positive** case: a realistic example string that should match
   - a **negative** case: something that looks similar but should *not*
     match (placeholder values, prose mentioning the term, values owned by
     another rule, etc.) - false positives are the most common complaint
     for this kind of tool, so negative cases matter as much as positive
     ones
3. Run `npm test` and confirm both the new cases and the full suite pass.
4. If the pattern is broad or user-suppliable (e.g. sourced from external
   data), consider ReDoS safety - avoid nested quantifiers over
   attacker-controlled input.

External regex rules sourced from `data/regex_list_1.json` are loaded
separately via `loadExternalRulesFromJson` and don't need code changes to
add - see the README's config reference for how they're filtered.

## The `dist/` rebuild requirement

`dist/` is committed to the repository (not gitignored) because Claude Code
plugins run the built JavaScript directly - there's no build step at
install time. **Any change under `src/` must be accompanied by a rebuild:**

```bash
npm run build
git add dist/
```

A PR that changes `src/` without a matching `dist/` change will leave the
installed plugin behavior out of sync with the source and will not be
merged.

## Release process

Releases are cut with:

```bash
make release
```

which runs `scripts/release.sh`. It interactively:

1. Prompts for a version bump (`patch` / `minor` / `major` / `custom`).
2. Syncs the new version into `.claude-plugin/plugin.json`.
3. Runs `npm run build` and `npm test`.
4. Prepends a `CHANGELOG.md` entry generated from commit subjects since the
   previous tag - review and edit the generated entry for clarity before
   confirming.
5. Creates a release commit and git tag.
6. Optionally pushes to `origin` and publishes to npm.

## Reporting issues

Please use the issue templates - the bug report template asks for what
was blocked and what you expected, and the false-positive template is for
the most common report type: a legitimate value that got flagged.
