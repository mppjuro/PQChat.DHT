#!/usr/bin/env bash
# Configure git hooks directory
set -euo pipefail

git config core.hooksPath .githooks
echo "Git hooks configured to .githooks directory."

if [[ "${1:-}" == "--with-release-tag-changelog" ]]; then
    git config pqchat.changelogOnReleaseTag true
    echo "Enabled optional CHANGELOG validation when pushing v* release tags (pqchat.changelogOnReleaseTag=true)."
fi
