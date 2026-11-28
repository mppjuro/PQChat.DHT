#!/usr/bin/env python3
"""
Generates CHANGELOG.md from git commit history following the Conventional Commits specification.
Groups commits into Features, Bug Fixes, Refactoring, Performance, Security, Documentation, Build/CI, and Tests.
Supports commit deduplication (after rebase/cherry-pick), delta ranges (--since / --since-last-tag),
validation (--check / --require-synced), custom output paths (--output), and --dry-run previewing.
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict

REPO_URL = "https://github.com/mppjuro/PQChat.DHT"

POLISH_DIACRITICS_RE = re.compile(
    r"[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c\u0104\u0106\u0118\u0141\u0143\u00d3\u015a\u0179\u017b]"
)

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


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def resolve_last_tag(glob_pattern="*", exclude_tag=None):
    """Resolves the most recent git tag matching glob_pattern, returning None if unavailable."""
    cmd = ["git", "tag", "--list", glob_pattern, "--sort=-creatordate"]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        tag = line.strip()
        if not tag:
            continue
        if exclude_tag and tag == exclude_tag:
            continue
        return tag
    return None


def resolve_since_range(since_ref=None, since_last_tag=None, exclude_tag=None):
    """Builds a safe git revision range '<base>..HEAD' or returns None for full history."""
    ref = since_ref
    if not ref and since_last_tag is not None:
        ref = resolve_last_tag(since_last_tag or "*", exclude_tag=exclude_tag)
    if not ref:
        return None

    # Verify ref resolves to a valid commit
    verify = subprocess.run(
        ["git", "rev-parse", "--verify", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if verify.returncode != 0:
        return None

    head_res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, encoding="utf-8")
    target_sha = verify.stdout.strip()
    if head_res.returncode == 0 and target_sha == head_res.stdout.strip():
        return f"{target_sha}..HEAD"

    anc = subprocess.run(["git", "merge-base", "--is-ancestor", target_sha, "HEAD"])
    if anc.returncode == 0:
        return f"{target_sha}..HEAD"

    mb = subprocess.run(["git", "merge-base", target_sha, "HEAD"], capture_output=True, text=True, encoding="utf-8")
    if mb.returncode == 0 and mb.stdout.strip():
        return f"{mb.stdout.strip()}..HEAD"
    return None


def get_git_commits(rev_range=None):
    # Format: Hash (full) %x1f Hash (short) %x1f Author %x1f Date (YYYY-MM-DD) %x1f Subject %x1e
    cmd = ["git", "log"]
    if rev_range:
        cmd.append(rev_range)
    cmd.extend(["--pretty=format:%H%x1f%h%x1f%an%x1f%ad%x1f%s%x1e", "--date=short"])
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
    if (
        subject.startswith("Merge pull request")
        or subject.startswith("Merge remote-tracking branch")
        or subject.startswith("Merge branch ")
    ):
        return True
    return False


def categorize_commit(subject):
    if is_ignored_commit(subject):
        return None

    for pattern, title, _ in CATEGORY_MAPPING:
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
        return desc if desc else subject.translate(DIACRITICS_MAP)
    return subject.translate(DIACRITICS_MAP)


def canonical_dedup_key(commit):
    """Normalizes (scope, title) to deduplicate rebased or cherry-picked commits."""
    formatted = format_subject(commit)
    # Strip trailing PR reference e.g. (#123) and trailing punctuation
    cleaned = re.sub(r"\s*\(#\d+\)\s*$", "", formatted)
    cleaned = re.sub(r"[.;:\s]+$", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lower()
    return cleaned


def deduplicate_commits(commits):
    """Preserves the newest commit for each unique normalized (scope, title) pair."""
    seen_keys = set()
    unique_commits = []
    duplicates_removed = 0
    for c in commits:
        if is_ignored_commit(c["subject"]):
            continue
        key = canonical_dedup_key(c)
        if key in seen_keys:
            duplicates_removed += 1
            continue
        seen_keys.add(key)
        unique_commits.append(c)
    return unique_commits, duplicates_removed


def generate_changelog(commits, include_header=True):
    unique_commits, duplicates_removed = deduplicate_commits(commits)
    categories = defaultdict(list)
    for c in unique_commits:
        cat = categorize_commit(c["subject"])
        if cat is None:
            continue
        categories[cat].append(c)

    lines = []
    if include_header:
        lines.extend([
            "# 📜 Changelog",
            "",
            "All notable changes to the **PQChat.DHT** project are documented in this file.",
            "The format is based on the [Conventional Commits](https://www.conventionalcommits.org/) specification.",
            "",
            "---",
            "",
        ])

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

    rendered = "\n".join(lines).strip()
    return (rendered + "\n") if rendered else "", len(unique_commits), duplicates_removed


def validate_changelog(generated_content, target_path, require_synced=False):
    errors = []
    if POLISH_DIACRITICS_RE.search(generated_content):
        errors.append("Generated changelog contains non-English diacritics.")

    if os.path.isfile(target_path):
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()
        for marker in ("<<<<<<<", "=======", ">>>>>>>"):
            if marker in existing:
                errors.append(f"Conflict marker '{marker}' found in {target_path}.")
        if POLISH_DIACRITICS_RE.search(existing):
            errors.append(f"Existing {target_path} contains non-English diacritics.")

        seen_entries = set()
        for line in existing.splitlines():
            m = re.match(r"^- \[`[^`]+`\]\([^)]+\)\s+\([^)]+\)\s+—\s+(.+)$", line.strip())
            if m:
                norm = re.sub(r"[.;:\s]+$", "", re.sub(r"\s+", " ", m.group(1))).strip().lower()
                if norm in seen_entries:
                    errors.append(f"Duplicate changelog entry in {target_path}: {m.group(1)}")
                seen_entries.add(norm)

        if require_synced and existing != generated_content:
            errors.append(f"{target_path} is out of sync with deduplicated git history.")
    elif require_synced:
        errors.append(f"Required changelog file missing: {target_path}")

    return errors


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate, deduplicate, and validate PQChat.DHT changelogs from git history."
    )
    parser.add_argument(
        "-o", "--output",
        default="CHANGELOG.md",
        help="Target output file path (default: CHANGELOG.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated changelog to stdout instead of writing to disk",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate changelog generation, deduplication, English cleanliness, and target file integrity",
    )
    parser.add_argument(
        "--require-synced",
        action="store_true",
        help="When combined with --check, require the existing output file to match generated output exactly",
    )
    parser.add_argument(
        "--since",
        default=None,
        help="Generate delta changelog from <REF>..HEAD",
    )
    parser.add_argument(
        "--since-last-tag",
        nargs="?",
        const="*",
        default=None,
        metavar="GLOB",
        help="Generate delta changelog since the most recent tag matching GLOB (default: '*')",
    )
    parser.add_argument(
        "--exclude-tag",
        default=None,
        help="Tag name to exclude when resolving --since-last-tag",
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Omit top-level CHANGELOG title banner (for embedding in GitHub Release notes)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    _configure_stdio()
    args = parse_args(argv)

    rev_range = resolve_since_range(
        since_ref=args.since,
        since_last_tag=args.since_last_tag,
        exclude_tag=args.exclude_tag,
    )
    commits = get_git_commits(rev_range=rev_range)
    content, unique_count, duplicates_removed = generate_changelog(
        commits,
        include_header=not args.no_header,
    )

    if args.check:
        errors = validate_changelog(content, args.output, require_synced=args.require_synced)
        if errors:
            for err in errors:
                print(f"[FAIL] {err}", file=sys.stderr)
            return 1
        print(
            f"[PASS] Changelog check succeeded ({len(commits)} commits scanned, "
            f"{unique_count} unique entries, {duplicates_removed} duplicate(s) removed)."
        )
        return 0

    if args.dry_run:
        sys.stdout.write(content)
        print(
            f"# [dry-run] {len(commits)} commits scanned, {unique_count} unique entries, "
            f"{duplicates_removed} duplicate(s) removed.",
            file=sys.stderr,
        )
        return 0

    parent_dir = os.path.dirname(args.output)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    print(
        f"Generated {args.output} successfully ({len(commits)} commits scanned, "
        f"{unique_count} unique entries, {duplicates_removed} duplicate(s) removed)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
