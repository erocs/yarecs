#!/usr/bin/env python3
"""
semgrep_triage.py — scan a semgrep community rules directory and categorise
each rule by how translatable it is to a yarecs regex rule.

Usage:
    python scripts/semgrep_triage.py <language-dir>

Examples:
    python scripts/semgrep_triage.py semgrep-rules/java
    python scripts/semgrep_triage.py semgrep-rules/rust

Output (stdout):
    Per-rule summary: [TAG] rule-id  --  first inline pattern (truncated)

Tags:
    TAINT   — mode: taint  (inter-statement data-flow, cannot be expressed as regex)
    REGEX   — has pattern-regex (may be directly usable)
    META    — uses $METAVAR patterns (AST matching, often translatable to regex for simple calls)
    SIMPLE  — pattern with no metavars (may be directly regex-translatable)
"""

import glob
import os
import re
import sys


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_rules(content):
    """
    Split a semgrep YAML file into individual rule blocks.
    Returns list of dicts with keys: id, severity, message, content, tags.
    """
    rules = []
    blocks = re.split(r"\n\s*- id:\s*", content)
    for i, block in enumerate(blocks):
        if i == 0:
            continue  # file header before first rule
        lines = block.split("\n")
        rule_id = lines[0].strip()

        sev_m = re.search(r"^severity:\s*(\S+)", block, re.MULTILINE)
        severity = sev_m.group(1).upper() if sev_m else "WARNING"

        # Message — handle multi-line >- blocks
        msg_m = re.search(
            r"^message:\s*>?-?\s*\n?(.*?)(?=\n\S|\Z)", block, re.MULTILINE | re.DOTALL
        )
        message = " ".join(msg_m.group(1).split()) if msg_m else ""

        has_taint = "mode: taint" in block
        has_metavar = bool(re.search(r"\$[A-Z_]{2,}", block))
        has_pattern_regex = "pattern-regex:" in block

        pats_inline = re.findall(
            r"  pattern(?:-regex|-either|-not|-inside)?:\s*([^\n|>]+)", block
        )

        rules.append(
            {
                "id": rule_id,
                "severity": severity,
                "message": message[:100],
                "has_taint": has_taint,
                "has_metavar": has_metavar,
                "has_pattern_regex": has_pattern_regex,
                "inline_patterns": [p.strip() for p in pats_inline[:3] if p.strip() and p.strip() not in (">", "|", ">-", "|-")],
                "content": block,
            }
        )
    return rules


def triage_tag(rule):
    if rule["has_taint"]:
        return "TAINT"
    if rule["has_pattern_regex"]:
        return "REGEX"
    if rule["has_metavar"]:
        return "META"
    return "SIMPLE"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    target_dir = sys.argv[1]
    yaml_files = sorted(
        glob.glob(os.path.join(target_dir, "**", "*.yaml"), recursive=True)
        + glob.glob(os.path.join(target_dir, "**", "*.yml"), recursive=True)
    )

    print(f"Found {len(yaml_files)} YAML files under {target_dir}\n")

    all_rules = []
    for f in yaml_files:
        content = read(f)
        rules = parse_rules(content)
        for r in rules:
            r["file"] = f
        all_rules.extend(rules)

    print(f"Total rules: {len(all_rules)}\n")

    # Counts by tag
    from collections import Counter
    tag_counts = Counter(triage_tag(r) for r in all_rules)
    for tag, count in sorted(tag_counts.items()):
        print(f"  {tag:8s} {count}")
    print()

    # Detailed listing
    for r in all_rules:
        tag = triage_tag(r)
        print(f"[{tag}] {r['id']}")
        for p in r["inline_patterns"]:
            print(f"    {p[:90]}")


if __name__ == "__main__":
    main()
