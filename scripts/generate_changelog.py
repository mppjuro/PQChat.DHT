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
    (r"^(feat|feature)(\(.*\))?!?:", "🚀 Nowe Funkcjonalności (Features)", "feat"),
    (r"^(fix)(\(.*\))?!?:", "🐛 Poprawki Błędów (Bug Fixes)", "fix"),
    (r"^(refactor)(\(.*\))?!?:", "♻️ Refaktoryzacja (Refactoring)", "refactor"),
    (r"^(perf|performance)(\(.*\))?!?:", "⚡ Wydajność i Optymalizacje (Performance)", "perf"),
    (r"^(sec|security)(\(.*\))?!?:", "🔒 Bezpieczeństwo i Kryptografia (Security)", "security"),
    (r"^(docs|doc)(\(.*\))?!?:", "📚 Dokumentacja (Documentation)", "docs"),
    (r"^(test|tests)(\(.*\))?!?:", "🧪 Testy (Tests)", "test"),
    (r"^(build|ci|deps|dependabot)(\(.*\))?!?:", "📦 Budowanie i Zależności (Build & CI)", "build"),
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

def categorize_commit(subject):
    # Check if merge commit of a dependabot PR
    if subject.startswith("Merge pull request") or subject.startswith("Merge remote-tracking branch"):
        return None  # Skip merge commits in changelog

    for pattern, title, key in CATEGORY_MAPPING:
        if re.search(pattern, subject, re.IGNORECASE):
            return title

    # Fallback heuristic based on keywords
    sub_lower = subject.lower()
    if sub_lower.startswith("harden") or "security" in sub_lower or "keystore" in sub_lower:
        return "🔒 Bezpieczeństwo i Kryptografia (Security)"
    if sub_lower.startswith("add ") or sub_lower.startswith("introduce "):
        return "🚀 Nowe Funkcjonalności (Features)"
    if sub_lower.startswith("fix ") or sub_lower.startswith("eliminate "):
        return "🐛 Poprawki Błędów (Bug Fixes)"
    if sub_lower.startswith("optimize "):
        return "⚡ Wydajność i Optymalizacje (Performance)"
    if "license" in sub_lower or "readme" in sub_lower or "doc" in sub_lower:
        return "📚 Dokumentacja (Documentation)"
    if "workflow" in sub_lower or "dependabot" in sub_lower or "gradle" in sub_lower:
        return "📦 Budowanie i Zależności (Build & CI)"

    return "🛠️ Pozostałe Zmiany (Other Changes)"

def format_subject(subject):
    # Highlight scopes nicely, e.g. feat(tor): foo -> **tor**: foo
    m = re.match(r"^[a-zA-Z]+(\([^\)]+\))?!?:?\s*(.*)$", subject)
    if m:
        scope = m.group(1)
        desc = m.group(2)
        if scope:
            clean_scope = scope.strip("()")
            return f"**{clean_scope}**: {desc}" if desc else f"**{clean_scope}**"
        return desc if desc else subject
    return subject

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
        "Wszystkie istotne zmiany w projekcie **PQChat.DHT** są rejestrowane w tym dokumencie.",
        "Format jest oparty na specyfikacji [Conventional Commits](https://www.conventionalcommits.org/).",
        "",
        "---",
        "",
    ]

    # Pre-defined ordered categories
    ordered_cats = [
        "🚀 Nowe Funkcjonalności (Features)",
        "🔒 Bezpieczeństwo i Kryptografia (Security)",
        "🐛 Poprawki Błędów (Bug Fixes)",
        "⚡ Wydajność i Optymalizacje (Performance)",
        "♻️ Refaktoryzacja (Refactoring)",
        "📦 Budowanie i Zależności (Build & CI)",
        "🧪 Testy (Tests)",
        "📚 Dokumentacja (Documentation)",
        "🛠️ Pozostałe Zmiany (Other Changes)",
    ]

    for cat in ordered_cats:
        commit_list = categories.get(cat, [])
        if not commit_list:
            continue

        lines.append(f"## {cat}")
        lines.append("")
        for c in commit_list:
            formatted_desc = format_subject(c["subject"])
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
