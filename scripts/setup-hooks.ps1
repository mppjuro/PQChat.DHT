param(
    [switch]$WithReleaseTagChangelog
)

# Configure git hooks directory
git config core.hooksPath .githooks
Write-Host "Git hooks configured to .githooks directory."

if ($WithReleaseTagChangelog) {
    git config pqchat.changelogOnReleaseTag true
    Write-Host "Enabled optional CHANGELOG validation when pushing v* release tags (pqchat.changelogOnReleaseTag=true)."
}
