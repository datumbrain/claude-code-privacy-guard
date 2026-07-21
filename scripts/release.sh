#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

previous_tag="$(git describe --tags --abbrev=0 2>/dev/null || echo "")"
current_version="$(npm pkg get version | tr -d '"')"

echo "Current version: ${current_version}"
echo "Choose version bump: patch | minor | major | custom"
read -r -p "Bump type [patch]: " bump_type
bump_type="${bump_type:-patch}"

new_version=""

case "$bump_type" in
  patch|minor|major)
    npm version "$bump_type" --no-git-tag-version >/dev/null
    ;;
  custom)
    read -r -p "Enter version (e.g. 1.2.3): " custom_version
    if [[ -z "${custom_version}" ]]; then
      echo "No version provided. Aborting."
      exit 1
    fi
    npm version "$custom_version" --no-git-tag-version >/dev/null
    ;;
  *)
    echo "Invalid bump type: ${bump_type}"
    exit 1
    ;;
esac

new_version="$(npm pkg get version | tr -d '"')"

echo "Syncing .claude-plugin/plugin.json version..."
node -e '
  const fs = require("fs");
  const path = ".claude-plugin/plugin.json";
  const plugin = JSON.parse(fs.readFileSync(path, "utf8"));
  plugin.version = process.argv[1];
  fs.writeFileSync(path, JSON.stringify(plugin, null, 2) + "\n");
' "$new_version"

echo "Prepared release version: ${new_version}"
read -r -p "Continue with build, test, commit, and tag? [y/N]: " confirm_release

if [[ ! "$confirm_release" =~ ^[Yy]$ ]]; then
  echo "Release canceled."
  exit 0
fi

echo "Running build..."
npm run build

echo "Running tests..."
npm test -- --runInBand

echo "Updating CHANGELOG.md..."
log_range="HEAD"
if [[ -n "${previous_tag}" ]]; then
  log_range="${previous_tag}..HEAD"
fi
changelog_entries="$(git log "${log_range}" --no-merges --pretty=format:'- %s' -- . ':!CHANGELOG.md')"
if [[ -z "${changelog_entries}" ]]; then
  changelog_entries="- No changes recorded"
fi
release_date="$(date +%Y-%m-%d)"
if [[ ! -f CHANGELOG.md ]]; then
  echo "# Changelog" > CHANGELOG.md
fi
existing_entries="$(tail -n +2 CHANGELOG.md)"
{
  echo "# Changelog"
  echo ""
  echo "## v${new_version} - ${release_date}"
  echo ""
  echo "${changelog_entries}"
  echo ""
  echo "${existing_entries}"
} > CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

echo "Creating git commit and tag..."
git add -A
git commit -m "release: v${new_version}"
git tag "${new_version}"

read -r -p "Push commit and tags to origin? [y/N]: " confirm_push
if [[ "$confirm_push" =~ ^[Yy]$ ]]; then
  git push
  git push --tags
fi

echo "Release complete: v${new_version}"
