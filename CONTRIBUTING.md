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
4. If a regex alone is too loose (checksums, entropy), pair it with the
   optional `validate(match, groups)` function on the rule: the scanner drops
   any match it rejects. See `src/scanner/pii.ts` (Luhn, SSN ranges) and
   `src/scanner/entropy.ts` for examples.
5. If the pattern is broad or user-suppliable (e.g. sourced from external
   data), consider ReDoS safety - avoid nested quantifiers over
   attacker-controlled input.

External rules live in `data/gitleaks-rules.json`, converted from
[gitleaks](https://github.com/gitleaks/gitleaks)' MIT-licensed default config
(license kept in `data/gitleaks-LICENSE`). Don't edit the JSON by hand;
regenerate it from a pinned gitleaks release:

```bash
curl -fsSL -o /tmp/gitleaks.toml \
  https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml
npm run build
node scripts/convert-gitleaks-rules.mjs /tmp/gitleaks.toml data/gitleaks-rules.json
```

The script translates Go RE2 syntax to JavaScript and drops (with a reason)
any rule that doesn't compile, fails safe-regex2, matches the empty string,
or is slow on adversarial input (`src/scanner/regex-audit.ts`). The test
suite runs the same slow-input audit over every shipped rule, so a regex that
goes quadratic fails CI.

## The `dist/` rebuild requirement

`dist/` is committed to the repository (not gitignored) because Claude Code
plugins run the built JavaScript directly - there's no build step at
install time. **Any change under `src/` must be accompanied by a rebuild:**

```bash
npm run build
git add dist/
```

`dist/` is a generated artifact, not something reviewers read. It's marked
`linguist-generated` in `.gitattributes`, so GitHub collapses it in PR diffs
- reviewers look at `src/` only. Correctness is enforced mechanically instead:
CI runs a clean `npm run build` and **fails the PR if the committed `dist/`
doesn't match**, so a stale or hand-edited `dist/` cannot be merged. Just
rebuild and commit; don't worry about the diff being unreadable.

Source maps are intentionally disabled (`sourceMap` / `declarationMap` off in
`tsconfig.json`) - they add no value to a shipped plugin and only bloated the
diff, so no `*.map` files should ever appear under `dist/`.

## Release process

Releases are cut with:

```bash
make release
```

which runs `scripts/release.sh`. Every prompt takes a single keypress (no
Enter), and only `y` counts as yes. It:

1. Refuses to run on a dirty working tree.
2. Prompts for a version bump: `1` patch, `2` minor, `3` major (any other key
   cancels), and refuses if that tag already exists locally or on `origin`.
   Nothing on disk changes before you confirm.
3. Runs `npm run build` and `npm test`.
4. Syncs the new version into `.claude-plugin/plugin.json` and
   `.claude-plugin/marketplace.json`.
5. Creates the `release: vX.Y.Z` commit.
6. Optionally pushes to `origin` and creates the GitHub release (which also
   creates the tag) with auto-generated notes.
7. Only after the GitHub release, optionally publishes to npm. This is
   opt-in and defaults to **No** at every prompt: it checks `npm whoami`,
   runs `npm publish --dry-run` so you can inspect the tarball, then asks
   once more before the real `npm publish`. Publishing needs an npm account
   with publish rights to `claude-code-privacy-guard` (and its 2FA, if
   enabled, will prompt for an OTP).

## Reporting issues

Please use the issue templates - the bug report template asks for what
was blocked and what you expected, and the false-positive template is for
the most common report type: a legitimate value that got flagged.
