#!/usr/bin/env python3
"""
BAY-SEC Solutions: Batch Repository Auditor
Clones remote repositories or scans local target directories, filtering out third-party libs,
and outputs triage summaries in Markdown and unified SARIF format.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List
from static_security_auditor import StaticSecurityAuditor, build_sarif_log

IGNORED_DIRS = {
    "node_modules",
    "lib",
    "forge-std",
    "openzeppelin-contracts",
    "build",
    "test",
    "tests",
    ".git",
    "venv",
    ".venv",
}


def is_ignored(path: str) -> bool:
    parts = set(os.path.normpath(path).split(os.sep))
    return bool(parts.intersection(IGNORED_DIRS))


def collect_target_files(directories: List[str]) -> List[str]:
    valid_files = []
    for d in directories:
        if os.path.isfile(d):
            if not is_ignored(d) and d.endswith((".sol", ".circom")):
                valid_files.append(d)
        elif os.path.isdir(d):
            for root, _, files in os.walk(d):
                if is_ignored(root):
                    continue
                for f in files:
                    if f.endswith((".sol", ".circom")):
                        full_path = os.path.join(root, f)
                        if not is_ignored(full_path):
                            valid_files.append(full_path)
    return valid_files


def clone_repo(repo_url: str, dest_dir: str) -> bool:
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, dest_dir],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except Exception as e:
        print(f"Failed to clone {repo_url}: {e}")
        return False


def generate_markdown_report(all_findings: Dict[str, List[Dict[str, Any]]], output_path: str) -> None:
    md_lines = [
        "# 🛡️ BAY-SEC Security Triage Report",
        "",
        "| Rule ID | Severity | Category | Target File | Line | Issue |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    total_count = 0
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    
    flat_findings = []
    for filepath, findings in all_findings.items():
        for f in findings:
            flat_findings.append((filepath, f))
            total_count += 1

    flat_findings.sort(key=lambda x: severity_order.get(x[1].get("severity", "LOW"), 4))

    for filepath, f in flat_findings:
        md_lines.append(
            f"| `{f['ruleId']}` | **{f['severity']}** | {f['category']} | `{filepath}` | {f['line']} | {f['title']} |"
        )

    md_lines.append("")
    md_lines.append(f"**Total Findings Detected:** {total_count}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))
    print(f"Markdown report generated at {output_path}")


def main():
    parser = argparse.ArgumentParser(description="BAY-SEC Batch Repository & Directory Security Auditor")
    parser.add_argument("--dirs", nargs="+", help="Local directory paths to scan")
    parser.add_argument("--repos", nargs="+", help="Remote Git repository URLs to clone and scan")
    parser.add_argument("--repo-list", help="Text file containing list of Git repository URLs")
    parser.add_argument("--output-md", default="audit_triage_report.md", help="Path for output Markdown report")
    parser.add_argument("--output-sarif", default="results.sarif", help="Path for output SARIF report")

    args = parser.parse_args()
    all_findings: Dict[str, List[Dict[str, Any]]] = {}
    temp_dir = tempfile.mkdtemp(prefix="baysec_batch_")

    try:
        targets_to_scan = []
        if args.dirs:
            targets_to_scan.extend(args.dirs)

        repo_urls = []
        if args.repos:
            repo_urls.extend(args.repos)
        if args.repo_list and os.path.exists(args.repo_list):
            with open(args.repo_list, "r", encoding="utf-8") as f:
                repo_urls.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

        for url in repo_urls:
            repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
            dest = os.path.join(temp_dir, repo_name)
            print(f"Cloning {url} -> {dest}...")
            if clone_repo(url, dest):
                targets_to_scan.append(dest)

        files = collect_target_files(targets_to_scan)
        print(f"Scanning {len(files)} target files across active targets...")

        for file_path in files:
            scanner = StaticSecurityAuditor(file_path)
            findings = scanner.run()
            if findings:
                all_findings[file_path] = findings

        generate_markdown_report(all_findings, args.output_md)
        sarif_log = build_sarif_log(all_findings)
        with open(args.output_sarif, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2)
        print(f"SARIF log generated at {args.output_sarif}")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
