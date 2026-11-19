#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Single-keypress prompts: no Enter needed. Anything but y/Y (Enter included)
# is "no", so tapping through can never publish by accident.
ask() {
  local key
  read -r -n 1 -s -p "$1 [y/N] " key || true
  echo "${key}"
  [[ "$key" == [Yy] ]]
}

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash first."
  exit 1
fi

current="$(node -p 'require("./package.json").version')"
IFS=. read -r maj min pat <<<"$current"

echo "Current version: ${current}"
echo "  1) patch  ${maj}.${min}.$((pat + 1))"
echo "  2) minor  ${maj}.$((min + 1)).0"
echo "  3) major  $((maj + 1)).0.0"
read -r -n 1 -s -p "Bump: " choice || true
case "$choice" in
  1) version="${maj}.${min}.$((pat + 1))" ;;
  2) version="${maj}.$((min + 1)).0" ;;
  3) version="$((maj + 1)).0.0" ;;
  *) echo; echo "Canceled."; exit 0 ;;
esac
echo "${version}"

git fetch -q --tags
if git rev-parse -q --verify "refs/tags/${version}" >/dev/null || git ls-remote --exit-code --tags origin "${version}" >/dev/null; then
  echo "Tag ${version} already exists. Aborting."
  exit 1
fi

# Nothing on disk changes before this confirmation.
ask "Build, test and commit release ${version}?" || { echo "Canceled. No files were modified."; exit 0; }

npm run build
npm test -- --runInBand

# Bump package.json and the plugin manifests together.
npm version "$version" --no-git-tag-version --allow-same-version >/dev/null
node -e '
  const fs = require("fs");
  const v = process.argv[1];
  const write = (p, f) => { const j = JSON.parse(fs.readFileSync(p, "utf8")); f(j); fs.writeFileSync(p, JSON.stringify(j, null, 2) + "\n"); };
  write(".claude-plugin/plugin.json", (j) => { j.version = v; });
  write(".claude-plugin/marketplace.json", (j) => { for (const p of j.plugins) p.version = v; });
' "$version"

git add -A
git commit -m "release: v${version}"

if ! ask "Push and publish GitHub release ${version}?"; then
  echo "Release commit created locally. To publish later:"
  echo "  git push && gh release create ${version} --title ${version} --generate-notes --latest"
  exit 0
fi

# gh creates the tag and the Releases entry; notes come from merged PRs.
git push
gh release create "$version" --title "$version" --target "$(git rev-parse HEAD)" --generate-notes --latest
echo "Published: https://github.com/datumbrain/claude-code-privacy-guard/releases/tag/${version}"

# npm is opt-in, needs a login, and dry-runs before the irreversible publish
# (npm versions can never be reused).
if ask "Also publish to npm?"; then
  if npm_user="$(npm whoami 2>/dev/null)"; then
    echo "Logged in to npm as ${npm_user}. Dry run:"
    npm publish --dry-run
    if ask "Publish claude-code-privacy-guard@${version} to npm for real?"; then
      npm publish
      echo "Published: https://www.npmjs.com/package/claude-code-privacy-guard/v/${version}"
      exit 0
    fi
  else
    echo "Not logged in to npm (run 'npm login')."
  fi
fi
echo "npm publish skipped. To publish later: npm publish"
