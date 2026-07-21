#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

current_version="$(npm pkg get version | tr -d '"')"

echo "Current version: ${current_version}"
echo "Choose version bump: patch | minor | major | custom"
read -r -p "Bump type [patch]: " bump_type
bump_type="${bump_type:-patch}"

# Compute the next version WITHOUT writing any files. The previous script ran
# `npm version` (which rewrites package.json) *before* the confirmation gate, so
# a canceled release left the version bumped on disk and that number was then
# consumed by the next run - that is exactly how v0.2.2 got skipped. Nothing on
# disk is modified until after the confirmation below.
#
# Note: `npm version --dry-run` is NOT used here - in the npm shipped with this
# toolchain it ignores --dry-run and mutates package.json anyway. We compute the
# next semver ourselves instead.
case "$bump_type" in
  patch|minor|major)
    new_version="$(node -e '
      const [maj, min, pat] = process.argv[1].split(".").map(Number);
      const bump = process.argv[2];
      const next = bump === "major" ? `${maj + 1}.0.0`
                 : bump === "minor" ? `${maj}.${min + 1}.0`
                 : `${maj}.${min}.${pat + 1}`;
      process.stdout.write(next);
    ' "$current_version" "$bump_type")"
    ;;
  custom)
    read -r -p "Enter version (e.g. 1.2.3): " new_version
    new_version="${new_version#v}"
    if [[ -z "${new_version}" ]]; then
      echo "No version provided. Aborting."
      exit 1
    fi
    ;;
  *)
    echo "Invalid bump type: ${bump_type}"
    exit 1
    ;;
esac

echo "Prepared release version: ${new_version}"
read -r -p "Build, test, and create the release commit? [y/N]: " confirm_release
if [[ ! "$confirm_release" =~ ^[Yy]$ ]]; then
  echo "Release canceled. No files were modified."
  exit 0
fi

echo "Running build..."
npm run build

echo "Running tests..."
npm test -- --runInBand

# Only now, after build+test pass and the user has confirmed, do we touch files.
echo "Applying version ${new_version}..."
npm version "$new_version" --no-git-tag-version --allow-same-version >/dev/null

echo "Syncing .claude-plugin/plugin.json version..."
node -e '
  const fs = require("fs");
  const path = ".claude-plugin/plugin.json";
  const plugin = JSON.parse(fs.readFileSync(path, "utf8"));
  plugin.version = process.argv[1];
  fs.writeFileSync(path, JSON.stringify(plugin, null, 2) + "\n");
' "$new_version"

echo "Creating release commit..."
git add -A
git commit -m "release: v${new_version}"

read -r -p "Push to origin and publish GitHub release v${new_version}? [y/N]: " confirm_publish
if [[ "$confirm_publish" =~ ^[Yy]$ ]]; then
  # gh release create makes the git tag on the remote AND the Releases page
  # entry in one step, and --generate-notes builds the notes from the PRs merged
  # since the previous release. This replaces the old `git tag` + `git push
  # --tags` + hand-maintained CHANGELOG.md.
  git push
  gh release create "${new_version}" \
    --title "${new_version}" \
    --target "$(git rev-parse HEAD)" \
    --generate-notes \
    --latest
  echo "Published: https://github.com/datumbrain/claude-code-privacy-guard/releases/tag/${new_version}"
else
  echo "Release commit created locally (not pushed). To publish later, run:"
  echo "  git push && gh release create ${new_version} --title ${new_version} --generate-notes --latest"
fi

echo "Release complete: v${new_version}"
