#!/usr/bin/env python3
"""
scan.py – count source files and run yarecs rule sets against a directory.

Usage:
    python scan.py <directory> --name <scan_name> [--format sarif]
                               [--yarecs <path>] [--exclude <dir> ...]
"""

import argparse
import collections
import glob
import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALL_EXTENSIONS = [
    'c', 'cpp', 'cc', 'cxx', 'h', 'hpp', 'hh',
    'cs', 'java', 'go', 'rs', 'kt', 'kts', 'swift', 'py',
]

# Each entry: language_tag -> (extensions_list, rule_files_list)
# extensions_list is what gets passed to --extensions; rule_files are relative
# to the yarecs working directory (the script's directory).
LANGUAGE_SCANS = [
    ('c_cpp',    ['c', 'cpp', 'cc', 'cxx', 'h', 'hpp', 'hh'],
                 ['rules/c_cpp_security.toml', 'rules/unreal_engine5.toml']),
    ('csharp',   ['cs'],
                 ['rules/csharp_security.toml']),
    ('java',     ['java'],
                 ['rules/java_security.toml']),
    ('go',       ['go'],
                 ['rules/go_security.toml']),
    ('rust',     ['rs'],
                 ['rules/rust_security.toml']),
    ('kotlin',   ['kt', 'kts'],
                 ['rules/kotlin_security.toml']),
    ('swift',    ['swift'],
                 []),  # no swift-specific rules yet; skip if empty
    ('python',   ['py'],
                 ['rules/python_security.toml']),
]

GENERIC_RULES = [
    'rules/generic_secrets.toml',
    'rules/generic_sql.toml',
    'rules/generic_shell.toml',
]

FORMAT_EXTENSIONS = {
    'sarif': 'sarif',
    'json':  'json',
    'csv':   'csv',
    'text':  'txt',
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_yarecs(hint: str | None) -> str:
    """Return path to yarecs binary, checking hint then common build locations."""
    candidates = []
    if hint:
        candidates.append(hint)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates += [
        os.path.join(script_dir, 'target', 'release', 'yarecs.exe'),
        os.path.join(script_dir, 'target', 'release', 'yarecs'),
        os.path.join(script_dir, 'target', 'debug', 'yarecs.exe'),
        os.path.join(script_dir, 'target', 'debug', 'yarecs'),
        'yarecs.exe',
        'yarecs',
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
        # Also try shutil.which for entries without path separators
        if os.sep not in c and not c.startswith('.'):
            import shutil
            found = shutil.which(c)
            if found:
                return found
    # Last resort: hope it's on PATH
    return 'yarecs'


def _glob_match(pattern: str, name: str) -> bool:
    """Simple glob match: * matches any sequence of non-separator characters."""
    import fnmatch
    return fnmatch.fnmatch(name, pattern)


def count_files(directory: str, exclude: list[str] | None = None) -> dict[str, int]:
    """Count files per extension under directory (recursive), honouring excludes."""
    counts: dict[str, int] = collections.defaultdict(int)
    exclude = exclude or []
    pattern = os.path.join(glob.escape(directory), '**', '*')
    for path in glob.glob(pattern, recursive=True):
        if not os.path.isfile(path):
            continue
        # Check every directory component against exclude patterns
        rel = os.path.relpath(path, directory)
        parts = rel.replace('\\', '/').split('/')
        if any(_glob_match(pat, part) for pat in exclude for part in parts[:-1]):
            continue
        ext = os.path.splitext(path)[1].lstrip('.').lower()
        if ext in ALL_EXTENSIONS:
            counts[ext] += 1
    return counts


def run_yarecs(yarecs: str, directory: str, config_files: list[str],
               extensions: list[str] | None, output_path: str,
               fmt: str, all_files: bool = False,
               exclude: list[str] | None = None) -> int:
    """Run yarecs and return the process exit code."""
    script_dir = os.path.dirname(os.path.abspath(__file__))

    cmd = [yarecs]
    for cf in config_files:
        cmd += ['--config', os.path.join(script_dir, cf)]
    cmd += ['--format', fmt, '--output', output_path]
    if all_files:
        cmd.append('--all-files')
    elif extensions:
        cmd += ['--extensions', ','.join(extensions)]
    for d in (exclude or []):
        cmd += ['--exclude', d]
    cmd.append(directory)

    print(f'  Running: {" ".join(cmd)}')
    result = subprocess.run(cmd)
    return result.returncode

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Count source files and run yarecs security scans.')
    parser.add_argument('directory',
                        help='Directory to scan')
    parser.add_argument('--name', required=True,
                        help='Scan name; used as the output file name prefix')
    parser.add_argument('--format', default='sarif',
                        choices=list(FORMAT_EXTENSIONS),
                        help='Output format passed to yarecs (default: sarif)')
    parser.add_argument('--yarecs', default=None,
                        help='Path to yarecs binary (auto-detected if omitted)')
    parser.add_argument('--exclude', action='append', default=[],
                        metavar='DIR',
                        help='Directory name to exclude (may be repeated; supports * wildcard)')
    args = parser.parse_args()

    directory = os.path.abspath(args.directory)
    if not os.path.isdir(directory):
        print(f'error: not a directory: {directory}', file=sys.stderr)
        sys.exit(1)

    yarecs = find_yarecs(args.yarecs)
    fmt = args.format
    file_ext = FORMAT_EXTENSIONS[fmt]

    # ------------------------------------------------------------------
    # 1. Count files
    # ------------------------------------------------------------------
    print(f'\n=== File counts under {directory} ===')
    counts = count_files(directory, args.exclude)
    if not counts:
        print('  (no supported source files found)')
    else:
        for ext in ALL_EXTENSIONS:
            n = counts.get(ext, 0)
            if n:
                print(f'  .{ext:<8} {n:>6} file{"s" if n != 1 else ""}')
        total = sum(counts.values())
        print(f'  {"total":<9} {total:>6} file{"s" if total != 1 else ""}')

    # ------------------------------------------------------------------
    # 2. Generic rules (secrets, SQL, shell) – all files
    # ------------------------------------------------------------------
    print(f'\n=== Generic scan (secrets / SQL / shell) ===')
    out_generic = f'{args.name}_generic.{file_ext}'
    rc = run_yarecs(yarecs, directory, GENERIC_RULES,
                    extensions=None, output_path=out_generic,
                    fmt=fmt, all_files=True, exclude=args.exclude)
    status = 'ok' if rc == 0 else f'exit {rc}'
    print(f'  -> {out_generic} [{status}]')

    # ------------------------------------------------------------------
    # 3. Language-specific rules (only for languages with files present)
    # ------------------------------------------------------------------
    print(f'\n=== Language-specific scans ===')
    for lang, exts, rule_files in LANGUAGE_SCANS:
        if not rule_files:
            continue  # no rules defined for this language yet
        present = [e for e in exts if counts.get(e, 0) > 0]
        if not present:
            print(f'  [{lang}] skipped (no .{"/".join(exts)} files found)')
            continue
        file_count = sum(counts.get(e, 0) for e in exts)
        print(f'\n  [{lang}] {file_count} file(s) — extensions: {", ".join("." + e for e in present)}')
        out_lang = f'{args.name}_{lang}.{file_ext}'
        rc = run_yarecs(yarecs, directory, rule_files,
                        extensions=present, output_path=out_lang,
                        fmt=fmt, all_files=False, exclude=args.exclude)
        status = 'ok' if rc == 0 else f'exit {rc}'
        print(f'  -> {out_lang} [{status}]')

    print('\nDone.')


if __name__ == '__main__':
    main()
