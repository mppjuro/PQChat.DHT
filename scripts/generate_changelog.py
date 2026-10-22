#!/usr/bin/env python3
"""
Generates CHANGELOG.md from git commit history following the Conventional Commits specification.
Groups commits into Features, Bug Fixes, Refactoring, Performance, Security, Documentation, Build/CI, and Tests.
"""

import subprocess
import re
import sys
from datetime import datetime
from collections import defaultdict

REPO_URL = "https://github.com/mppjuro/PQChat.DHT"

CATEGORY_MAPPING = [
    (r"^(feat|feature)(\(.*\))?!?:", "🚀 Features", "feat"),
    (r"^(fix)(\(.*\))?!?:", "🐛 Bug Fixes", "fix"),
    (r"^(refactor)(\(.*\))?!?:", "♻️ Refactoring", "refactor"),
    (r"^(perf|performance)(\(.*\))?!?:", "⚡ Performance & Optimizations", "perf"),
    (r"^(sec|security)(\(.*\))?!?:", "🔒 Security & Cryptography", "security"),
    (r"^(docs|doc)(\(.*\))?!?:", "📚 Documentation", "docs"),
    (r"^(test|tests)(\(.*\))?!?:", "🧪 Tests", "test"),
    (r"^(build|ci|deps|dependabot)(\(.*\))?!?:", "📦 Build & Dependencies", "build"),
]

def get_git_commits():
    # Format: Hash (full) %x1f Hash (short) %x1f Author %x1f Date (YYYY-MM-DD) %x1f Subject %x1e
    cmd = ["git", "log", "--pretty=format:%H%x1f%h%x1f%an%x1f%ad%x1f%s%x1e", "--date=short"]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        print(f"Error reading git log: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    
    raw_commits = result.stdout.strip().split("\x1e")
    commits = []
    for item in raw_commits:
        item = item.strip()
        if not item:
            continue
        parts = item.split("\x1f")
        if len(parts) >= 5:
            commits.append({
                "hash": parts[0],
                "short_hash": parts[1],
                "author": parts[2],
                "date": parts[3],
                "subject": parts[4].strip(),
            })
    return commits

def is_ignored_commit(subject):
    sub_lower = subject.lower()
    if "auto-update changelog.md" in sub_lower or "[skip ci]" in sub_lower:
        return True
    if subject.startswith("Merge pull request") or subject.startswith("Merge remote-tracking branch"):
        return True
    return False

def categorize_commit(subject):
    if is_ignored_commit(subject):
        return None

    for pattern, title, key in CATEGORY_MAPPING:
        if re.search(pattern, subject, re.IGNORECASE):
            return title

    # Fallback heuristic based on keywords
    sub_lower = subject.lower()
    if sub_lower.startswith("harden") or "security" in sub_lower or "keystore" in sub_lower:
        return "🔒 Security & Cryptography"
    if sub_lower.startswith("add ") or sub_lower.startswith("introduce "):
        return "🚀 Features"
    if sub_lower.startswith("fix ") or sub_lower.startswith("eliminate "):
        return "🐛 Bug Fixes"
    if sub_lower.startswith("optimize "):
        return "⚡ Performance & Optimizations"
    if "license" in sub_lower or "readme" in sub_lower or "doc" in sub_lower:
        return "📚 Documentation"
    if "workflow" in sub_lower or "dependabot" in sub_lower or "gradle" in sub_lower:
        return "📦 Build & Dependencies"

    return "🛠️ Other Changes"

COMMIT_HASH_TRANSLATIONS = {
    "b2e150e": "expand empirical telemetry module and research capabilities for master thesis",
    "01bcf5a": "add fullscreen image viewer with gallery save, single-line SAS, and contact name editing",
    "18c1a14": "implement Blind Cooperative Republishing in DHT as alternative to synthetic decoy traffic",
    "049f2f1": "add PNG8 compression with color quantization and gallery picker",
    "e968816": "research module: traffic shaping metrics, BEP 44 retention, group chats, measurement loop refactoring, firestore.rules hardening and research_analyzer.py script",
}

# Transliteration table using unicode code points to prevent raw characters in source
DIACRITICS_MAP = str.maketrans(
    "\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c\u0104\u0106\u0118\u0141\u0143\u00d3\u015a\u0179\u017b",
    "acelnoszzACELNOSZZ"
)

def format_subject(commit):
    short_h = commit.get("short_hash", "")
    subject = commit.get("subject", "")
    
    # Check if this specific commit has an English translation
    if short_h in COMMIT_HASH_TRANSLATIONS:
        m = re.match(r"^[a-zA-Z]+(\([^\)]+\))?!?:?\s*(.*)$", subject)
        if m and m.group(1):
            clean_scope = m.group(1).strip("()")
            return f"**{clean_scope}**: {COMMIT_HASH_TRANSLATIONS[short_h]}"
        return COMMIT_HASH_TRANSLATIONS[short_h]

    # Highlight scopes nicely, e.g. feat(tor): foo -> **tor**: foo
    m = re.match(r"^[a-zA-Z]+(\([^\)]+\))?!?:?\s*(.*)$", subject)
    if m:
        scope = m.group(1)
        desc = m.group(2)
        if desc:
            desc = desc.strip().translate(DIACRITICS_MAP)
        if scope:
            clean_scope = scope.strip("()")
            return f"**{clean_scope}**: {desc}" if desc else f"**{clean_scope}**"
        return desc if desc else subject
    return subject.translate(DIACRITICS_MAP)

def generate_changelog(commits):
    categories = defaultdict(list)
    for c in commits:
        cat = categorize_commit(c["subject"])
        if cat is None:
            continue
        categories[cat].append(c)

    lines = [
        "# 📜 Changelog",
        "",
        "All notable changes to the **PQChat.DHT** project are documented in this file.",
        "The format is based on the [Conventional Commits](https://www.conventionalcommits.org/) specification.",
        "",
        "---",
        "",
    ]

    # Pre-defined ordered categories
    ordered_cats = [
        "🚀 Features",
        "🔒 Security & Cryptography",
        "🐛 Bug Fixes",
        "⚡ Performance & Optimizations",
        "♻️ Refactoring",
        "📦 Build & Dependencies",
        "🧪 Tests",
        "📚 Documentation",
        "🛠️ Other Changes",
    ]

    for cat in ordered_cats:
        commit_list = categories.get(cat, [])
        if not commit_list:
            continue

        lines.append(f"## {cat}")
        lines.append("")
        for c in commit_list:
            formatted_desc = format_subject(c)
            hash_link = f"[`{c['short_hash']}`]({REPO_URL}/commit/{c['hash']})"
            date_str = c["date"]
            lines.append(f"- {hash_link} ({date_str}) — {formatted_desc}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"

def main():
    commits = get_git_commits()
    content = generate_changelog(commits)
    
    target_path = "CHANGELOG.md"
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(content)
    
    print(f"Generated {target_path} successfully ({len(commits)} commits processed).")

if __name__ == "__main__":
    main()
