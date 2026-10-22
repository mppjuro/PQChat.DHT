#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Language Unification Verification Linter.

Verifies that no Polish characters exist in source code,
configuration, tests, scripts, or documentation across the repository.

Exemption:
- README.md BibTeX citation block: author name and university.
"""

import os
import re
import subprocess
import sys

# Polish diacritics in unicode escape form so that this script contains no raw characters
POLISH_CHARS_REGEX = re.compile(r'[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c\u0104\u0106\u0118\u0141\u0143\u00d3\u015a\u0179\u017b]')

IGNORED_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp',
    '.pdf', '.apk', '.bin', '.keystore', '.jks',
    '.jar', '.aar', '.class', '.so', '.dylib', '.dll', '.exe',
    '.zip', '.tar', '.gz', '.7z'
}

IGNORED_PATHS = {
    '.git', '.gradle', 'build', '.idea', '.venv', 'venv', 'node_modules'
}

def is_ignored_path(path: str) -> bool:
    normalized = path.replace('\\', '/')
    parts = normalized.split('/')
    for ignored in IGNORED_PATHS:
        if ignored in parts:
            return True
    ext = os.path.splitext(path)[1].lower()
    if ext in IGNORED_EXTENSIONS:
        return True
    return False

def get_tracked_files():
    try:
        output = subprocess.check_output(['git', 'ls-files'], text=True, encoding='utf-8')
        files = [line.strip() for line in output.splitlines() if line.strip()]
        return files
    except Exception as e:
        print(f"[WARN] Failed to get files via git: {e}. Falling back to os.walk().")
        all_files = []
        for root, dirs, filenames in os.walk('.'):
            # prune ignored dirs
            dirs[:] = [d for d in dirs if d not in IGNORED_PATHS]
            for fname in filenames:
                all_files.append(os.path.relpath(os.path.join(root, fname), '.'))
        return all_files

def is_exempt_line(file_path: str, line: str) -> bool:
    norm_path = file_path.replace('\\', '/')
    # Exemption for README.md BibTeX citation author name and university
    if norm_path == 'README.md' or norm_path.endswith('/README.md'):
        if '\u0141' in line or '\u0142' in line or '\u00f3' in line or '\u0144' in line:
            if 'author = {' in line or 'school = {' in line or 'Milosz' in line.replace('\u0142', 'l') or 'Torun' in line.replace('\u0144', 'n'):
                return True
        if 'author = {' in line or 'school = {' in line:
            return True
    return False

def check_files():
    files = get_tracked_files()
    violations = {}
    total_violation_count = 0

    for file_path in files:
        if is_ignored_path(file_path):
            continue
        if not os.path.isfile(file_path):
            continue

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if is_exempt_line(file_path, line):
                        continue
                    matches = POLISH_CHARS_REGEX.findall(line)
                    if matches:
                        if file_path not in violations:
                            violations[file_path] = []
                        violations[file_path].append((line_num, line.strip(), sorted(list(set(matches)))))
                        total_violation_count += len(matches)
        except UnicodeDecodeError:
            # Skip non-UTF8/binary files that weren't caught by extension
            continue

    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    if hasattr(sys.stderr, 'reconfigure'):
        try:
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    if violations:
        print("=" * 80)
        print(f"[FAIL] LANGUAGE UNIFICATION CHECK FAILED: {total_violation_count} Polish characters found across {len(violations)} files!")
        print("=" * 80)
        for path, items in violations.items():
            print(f"\nFile: {path} ({len(items)} violating lines)")
            for line_num, text, chars in items[:10]:
                print(f"  Line {line_num:4d} [{', '.join(chars)}]: {text}")
            if len(items) > 10:
                print(f"  ... and {len(items) - 10} more lines.")
        print("\nAll code, comments, documentation, and UI strings must be unified to 100% English.")
        return 1
    else:
        print("=" * 80)
        print("[SUCCESS] 100% English Language Unification verified!")
        print("Zero unauthorized Polish characters found across the entire repository.")
        print("=" * 80)
        return 0

if __name__ == '__main__':
    sys.exit(check_files())
