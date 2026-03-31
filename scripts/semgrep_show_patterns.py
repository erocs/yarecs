#!/usr/bin/env python3
"""
semgrep_show_patterns.py — print the full pattern block for specific rules
within a semgrep language directory.  Use this to inspect a rule before
deciding whether it can be translated to a yarecs regex.

Usage:
    python scripts/semgrep_show_patterns.py <language-dir> [rule-id ...]

Examples:
    # Show all rules whose id contains "crypto"
    python scripts/semgrep_show_patterns.py semgrep-rules/java crypto

    # Show specific rules by exact id
    python scripts/semgrep_show_patterns.py semgrep-rules/go use-of-md5 jwt-none-alg

    # Show everything (verbose — pipe to less)
    python scripts/semgrep_show_patterns.py semgrep-rules/csharp
"""

import glob
import os
import re
import sys

# Metadata-only lines we strip to reduce noise
SKIP_RE = re.compile(
    r"^\s+(?:cwe|owasp|source-rule-url|category|technology|references?|"
    r"subcategory|likelihood|impact|confidence|asvs|functional-categories|"
    r"cwe20\d\d-top25):",
    re.IGNORECASE,
)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def strip_metadata(content):
    return "\n".join(
        line for line in content.splitlines() if not SKIP_RE.match(line)
    )


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target_dir = sys.argv[1]
    filters = [f.lower() for f in sys.argv[2:]]  # optional id substrings

    yaml_files = sorted(
        glob.glob(os.path.join(target_dir, "**", "*.yaml"), recursive=True)
        + glob.glob(os.path.join(target_dir, "**", "*.yml"), recursive=True)
    )

    for f in yaml_files:
        content = read(f)
        blocks = re.split(r"\n\s*- id:\s*", content)
        for i, block in enumerate(blocks):
            if i == 0:
                continue
            rule_id = block.split("\n")[0].strip()

            # Filter by supplied ids (substring match, case-insensitive)
            if filters and not any(flt in rule_id.lower() for flt in filters):
                continue

            clean = strip_metadata(block)
            # Show only up to the first ~40 meaningful lines
            lines = [l for l in clean.splitlines() if l.strip()][:40]
            print(f"\n{'='*60}")
            print(f"FILE : {f}")
            print(f"RULE : {rule_id}")
            print("="*60)
            print("\n".join(lines))


if __name__ == "__main__":
    main()
