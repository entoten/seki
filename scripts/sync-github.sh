#!/bin/bash
# Sync to GitHub, excluding internal-only files.
# Usage: ./scripts/sync-github.sh
#
# Keeps Gitea's main intact. Creates a filtered branch and pushes to GitHub.

set -euo pipefail

GITHUB_REMOTE="github"
BRANCH="main"
TEMP_BRANCH="__github_sync"
SSH_CMD="ssh -i $HOME/.ssh/id_github_entoten -o IdentitiesOnly=yes"

# Files/dirs to exclude from GitHub (internal only)
EXCLUDE=(
  "talk/"
  "concept.md"
  ".company/"
  ".observer.lock"
  "seki-cli"
)

cd "$(git rev-parse --show-toplevel)"

# Ensure we're on main
CURRENT=$(git branch --show-current)
if [ "$CURRENT" != "$BRANCH" ]; then
  echo "ERROR: must be on $BRANCH branch (currently on $CURRENT)"
  exit 1
fi

# Clean up any previous temp branch
git branch -D "$TEMP_BRANCH" 2>/dev/null || true

# Create temp branch from current main
git checkout -b "$TEMP_BRANCH"

# Remove excluded paths
for path in "${EXCLUDE[@]}"; do
  if [ -e "$path" ]; then
    git rm -rf --quiet "$path" 2>/dev/null || true
  fi
done

# Commit the removal (amend onto HEAD so we don't create noise)
git commit --allow-empty -m "sync: remove internal-only files for GitHub" --quiet

# Force push to GitHub
GIT_SSH_COMMAND="$SSH_CMD" git push "$GITHUB_REMOTE" "${TEMP_BRANCH}:${BRANCH}" --force

# Switch back to main and clean up
git checkout "$BRANCH"
git branch -D "$TEMP_BRANCH"

echo ""
echo "Synced to GitHub (excluding: ${EXCLUDE[*]})"
echo "  GitHub: https://github.com/entoten/seki"
