#!/usr/bin/env bash
# Shared final publishing step. Only the explicitly supplied outputs are staged.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: publish-rulesets.sh COMMIT_MESSAGE OUTPUT..." >&2
  exit 2
fi
: "${GITHUB_TOKEN:?GITHUB_TOKEN is required for publication}"
message=$1
shift

git config user.name 'github-actions[bot]'
git config user.email 'github-actions[bot]@users.noreply.github.com'
git add -- "$@"
if git diff --cached --quiet; then
  echo 'No changes.'
  exit 0
fi
git commit -m "$message"

# Supply authentication to Git through its process environment. Never write a
# token into .git/config, a remote URL, or a command-line argument.
authorization=$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')
authenticated_git() {
  GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0=http.https://github.com/.extraheader \
    GIT_CONFIG_VALUE_0="AUTHORIZATION: basic ${authorization}" git "$@"
}

for attempt in 1 2 3 4 5; do
  if authenticated_git pull --rebase --autostash origin main; then
    # A rebase can change another rule pair or its manifest. Verify the actual
    # tree to be pushed; a validation failure must stop publication immediately.
    python3 scripts/verify-all.py
    if authenticated_git push origin HEAD:main; then
      echo "Pushed to main on attempt ${attempt}."
      exit 0
    fi
  else
    git rebase --abort 2>/dev/null || true
  fi
  echo "::warning::publish attempt ${attempt} failed, retrying with latest main..."
  if [[ $attempt -lt 5 ]]; then sleep $((attempt * 10)); fi
done
echo '::error::Failed to publish after 5 attempts.'
exit 1
