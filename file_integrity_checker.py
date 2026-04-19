"""
file_integrity_checker.py
=========================
Creates a hash baseline of files in a directory and detects
changes, additions, or deletions — mapped to MITRE T1565.

Usage:
  python file_integrity_checker.py baseline <directory> --output baseline.json
  python file_integrity_checker.py check <directory> --baseline baseline.json

Author: Poushali Majumder
"""

import os
import json
import hashlib
import argparse
from datetime import datetime


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Return hex digest of a file using specified algorithm."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, PermissionError):
        return "ERROR_UNREADABLE"


def build_baseline(directory: str, algorithm: str = "sha256") -> dict:
    """Walk directory and hash all files."""
    baseline = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, directory)
            baseline[rel_path] = {
                "hash": hash_file(filepath, algorithm),
                "size": os.path.getsize(filepath),
                "modified": os.path.getmtime(filepath),
            }
    return baseline


def check_integrity(directory: str, baseline: dict, algorithm: str = "sha256") -> dict:
    """Compare current state to baseline and return findings."""
    current = build_baseline(directory, algorithm)
    results = {"modified": [], "added": [], "deleted": []}

    for path, info in current.items():
        if path not in baseline:
            results["added"].append(path)
        elif info["hash"] != baseline[path]["hash"]:
            results["modified"].append({
                "file": path,
                "old_hash": baseline[path]["hash"],
                "new_hash": info["hash"],
            })

    for path in baseline:
        if path not in current:
            results["deleted"].append(path)

    return results


def main():
    parser = argparse.ArgumentParser(description="File Integrity Checker — MITRE T1565")
    subparsers = parser.add_subparsers(dest="command")

    # Baseline command
    base_parser = subparsers.add_parser("baseline", help="Create a hash baseline")
    base_parser.add_argument("directory", help="Directory to baseline")
    base_parser.add_argument("--output", default="baseline.json", help="Output file")
    base_parser.add_argument("--algorithm", default="sha256", choices=["md5", "sha1", "sha256"])

    # Check command
    check_parser = subparsers.add_parser("check", help="Check against baseline")
    check_parser.add_argument("directory", help="Directory to check")
    check_parser.add_argument("--baseline", default="baseline.json", help="Baseline file")
    check_parser.add_argument("--algorithm", default="sha256", choices=["md5", "sha1", "sha256"])

    args = parser.parse_args()

    print(f"\n{'='*55}")
    print("  FILE INTEGRITY CHECKER — MITRE T1565")
    print(f"{'='*55}")

    if args.command == "baseline":
        print(f"  Mode      : Creating baseline")
        print(f"  Directory : {args.directory}")
        print(f"  Algorithm : {args.algorithm.upper()}")
        print(f"  Output    : {args.output}\n")

        baseline = build_baseline(args.directory, args.algorithm)
        output = {
            "created": datetime.utcnow().isoformat() + "Z",
            "directory": os.path.abspath(args.directory),
            "algorithm": args.algorithm,
            "file_count": len(baseline),
            "files": baseline,
        }

        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)

        print(f"  ✅ Baseline created: {len(baseline)} files hashed")
        print(f"  Saved to: {args.output}\n")

    elif args.command == "check":
        print(f"  Mode      : Checking integrity")
        print(f"  Directory : {args.directory}")
        print(f"  Baseline  : {args.baseline}\n")

        with open(args.baseline) as f:
            data = json.load(f)
        baseline = data.get("files", {})
        algorithm = data.get("algorithm", args.algorithm)

        results = check_integrity(args.directory, baseline, algorithm)
        total = len(results["modified"]) + len(results["added"]) + len(results["deleted"])

        if total == 0:
            print("  ✅ Integrity check passed — no changes detected.\n")
        else:
            print(f"  ⚠️  {total} change(s) detected:\n")

            if results["modified"]:
                print(f"  MODIFIED ({len(results['modified'])}):")
                for item in results["modified"]:
                    print(f"  → {item['file']}")
                    print(f"    old: {item['old_hash']}")
                    print(f"    new: {item['new_hash']}")

            if results["added"]:
                print(f"\n  ADDED ({len(results['added'])}):")
                for path in results["added"]:
                    print(f"  → {path}")

            if results["deleted"]:
                print(f"\n  DELETED ({len(results['deleted'])}):")
                for path in results["deleted"]:
                    print(f"  → {path}")

        print(f"\n{'='*55}\n")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
