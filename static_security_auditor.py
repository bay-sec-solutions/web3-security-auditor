#!/usr/bin/env python3
"""
BAY-SEC Solutions: Static Security & Arithmetic Analysis Engine
Audits Solidity smart contracts (ERC-4626 / EVM) and Circom ZK circuits.
Outputs text reports or OASIS SARIF v2.1.0 logs for CI/CD integration.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List

RULES_METADATA = {
    "ARITH-001": {
        "id": "ARITH-001",
        "name": "DivideBeforeMultiply",
        "shortDescription": {"text": "Integer division before multiplication causes precision truncation."},
        "defaultConfiguration": {"level": "error"},
    },
    "ARITH-002": {
        "id": "ARITH-002",
        "name": "StrictEqualityOnDivision",
        "shortDescription": {"text": "Exact equality on division result is vulnerable to rounding DoS."},
        "defaultConfiguration": {"level": "warning"},
    },
    "ARITH-003": {
        "id": "ARITH-003",
        "name": "UncheckedIntegerDowncast",
        "shortDescription": {"text": "Downcasting large integer types without range bounds causes truncation."},
        "defaultConfiguration": {"level": "note"},
    },
    "VAULT-001": {
        "id": "VAULT-001",
        "name": "MissingCeilRoundingWithdrawal",
        "shortDescription": {"text": "ERC-4626 share calculation must round up on withdrawals/redemptions."},
        "defaultConfiguration": {"level": "error"},
    },
    "CIRCOM-001": {
        "id": "CIRCOM-001",
        "name": "UnconstrainedWitnessAssignment",
        "shortDescription": {"text": "Signal assigned via <-- without matching R1CS === constraint."},
        "defaultConfiguration": {"level": "error"},
    },
}


class StaticSecurityAuditor:
    def __init__(self, filepath: str):
        self.filepath = filepath
        with open(filepath, "r", encoding="utf-8") as f:
            self.raw_content = f.read()
        self.clean_code = self._strip_comments(self.raw_content)
        self.findings: List[Dict[str, Any]] = []

    def _strip_comments(self, src: str) -> str:
        def replacer(match):
            s = match.group(0)
            return "\n" * s.count("\n") if s.startswith("/*") else ""

        src = re.sub(r"/\*.*?\*/", replacer, src, flags=re.DOTALL)
        src = re.sub(r"//.*", "", src)
        return src

    def audit_solidity(self) -> None:
        lines = self.clean_code.splitlines()

        for idx, line in enumerate(lines, start=1):
            div_mul_pattern = (
                r"(\([^\)]+\/[^\)]+\)\s*\*|\b[a-zA-Z0-9_\.]+\s*\/\s*[a-zA-Z0-9_\.]+\s*\*)"
                r"\s*(?:\([^\)]+\)|[a-zA-Z0-9_\.]+)"
            )
            match = re.search(div_mul_pattern, line)
            if match:
                self.findings.append({
                    "ruleId": "ARITH-001",
                    "line": idx,
                    "severity": "HIGH",
                    "category": "Precision Loss",
                    "title": "Divide-Before-Multiply",
                    "snippet": match.group(0).strip(),
                    "remediation": "Reorder expression: compute `(a * c) / b` instead of `(a / b) * c`.",
                })

            strict_eq_pattern = r"(require|assert|if)\s*\([^;\)]*\/[^;\)]*==[^;\)]*\)"
            match_eq = re.search(strict_eq_pattern, line)
            if match_eq:
                self.findings.append({
                    "ruleId": "ARITH-002",
                    "line": idx,
                    "severity": "MEDIUM",
                    "category": "Rounding DoS",
                    "title": "Strict Equality on Division Output",
                    "snippet": match_eq.group(0).strip(),
                    "remediation": "Avoid exact `==` checks on division results. Use inequality bounds or tolerance ranges.",
                })

            downcast_pattern = r"\b(uint8|uint16|uint32|uint64|uint128)\s*\(\s*([a-zA-Z0-9_\.]+)\s*\)"
            match_cast = re.search(downcast_pattern, line)
            if match_cast:
                target_type, var_name = match_cast.group(1), match_cast.group(2)
                if not var_name.isdigit():
                    window = "\n".join(lines[max(0, idx - 4):idx])
                    guard_pattern = rf"require\s*\(\s*{var_name}\s*<=\s*(?:type\s*\(\s*{target_type}\s*\)\.max|2\*\*\d+|0x[0-9a-fA-F]+)"
                    if not re.search(guard_pattern, window):
                        self.findings.append({
                            "ruleId": "ARITH-003",
                            "line": idx,
                            "severity": "LOW",
                            "category": "Integer Truncation",
                            "title": f"Unchecked Downcast to {target_type}",
                            "snippet": match_cast.group(0).strip(),
                            "remediation": f"Ensure `{var_name} <= type({target_type}).max` prior to typecasting.",
                        })

        self._audit_erc4626_vault_rounding()

    def _audit_erc4626_vault_rounding(self) -> None:
        withdraw_func_pattern = (
            r"function\s+(?:previewWithdraw|_convertToShares|withdraw|previewRedeem)\s*\([^)]*\)[^{]*\{([^}]+)\}"
        )
        for match in re.finditer(withdraw_func_pattern, self.clean_code, re.DOTALL):
            func_body = match.group(1)
            line_offset = self.clean_code[:match.start()].count("\n") + 1

            has_div = "/" in func_body
            has_ceil = bool(
                re.search(r"\+\s*\(?[a-zA-Z0-9_.]+\s*-\s*1\)?", func_body)
                or "Rounding.Ceil" in func_body
                or ("Math.mulDiv" in func_body and "Math.Rounding.Ceil" in func_body)
            )

            if has_div and not has_ceil:
                self.findings.append({
                    "ruleId": "VAULT-001",
                    "line": line_offset,
                    "severity": "HIGH",
                    "category": "Vault Rounding Error",
                    "title": "Missing Round-Up in ERC-4626 Share Calculation",
                    "snippet": match.group(0).splitlines()[0].strip(),
                    "remediation": (
                        "Redemption/withdrawal calculations must round up: "
                        "`(assets * totalShares + totalAssets - 1) / totalAssets` or `Math.Rounding.Ceil`."
                    ),
                })

    def audit_circom(self) -> None:
        lines = self.clean_code.splitlines()
        signals = set()
        constrained_signals = set()
        unconstrained_assignments = []

        for idx, line in enumerate(lines, start=1):
            sig_match = re.search(r"signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)", line)
            if sig_match:
                signals.add(sig_match.group(1))

            assign_const_match = re.search(r"([a-zA-Z0-9_]+)\s*<==", line)
            if assign_const_match:
                constrained_signals.add(assign_const_match.group(1))

            if "===" in line:
                for sig in signals:
                    if re.search(rf"\b{sig}\b", line):
                        constrained_signals.add(sig)

            unconstrained_match = re.search(r"([a-zA-Z0-9_]+)\s*<--", line)
            if unconstrained_match:
                unconstrained_assignments.append((idx, unconstrained_match.group(1), line.strip()))

        for line_num, sig_name, snippet in unconstrained_assignments:
            if sig_name not in constrained_signals:
                self.findings.append({
                    "ruleId": "CIRCOM-001",
                    "line": line_num,
                    "severity": "CRITICAL",
                    "category": "Under-constrained Circuit",
                    "title": f"Unconstrained Signal '{sig_name}'",
                    "snippet": snippet,
                    "remediation": f"Enforce a corresponding R1CS equality constraint (`===`) on `{sig_name}`.",
                })

    def run(self) -> List[Dict[str, Any]]:
        ext = os.path.splitext(self.filepath)[1].lower()
        if ext == ".sol" or "pragma solidity" in self.clean_code:
            self.audit_solidity()
        elif ext == ".circom" or "pragma circom" in self.clean_code:
            self.audit_circom()
        return self.findings


def build_sarif_log(findings_by_file: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    sarif_rules = [
        {
            "id": r["id"],
            "name": r["name"],
            "shortDescription": r["shortDescription"],
            "defaultConfiguration": r["defaultConfiguration"],
        }
        for r in RULES_METADATA.values()
    ]

    sarif_results = []
    for filepath, findings in findings_by_file.items():
        for f in findings:
            rule_id = f.get("ruleId", "ARITH-001")
            sarif_results.append({
                "ruleId": rule_id,
                "level": level_map.get(f.get("severity", "HIGH"), "error"),
                "message": {"text": f"{f['title']}: {f['remediation']}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": filepath.replace("\\", "/")},
                        "region": {"startLine": f["line"]}
                    }
                }]
            })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BAY-SEC-Auditor",
                    "version": "1.2.0",
                    "rules": sarif_rules,
                }
            },
            "results": sarif_results,
        }]
    }


def main():
    parser = argparse.ArgumentParser(description="BAY-SEC Static Analyzer for Smart Contracts & ZK Circuits")
    parser.add_argument("targets", nargs="+", help="Target file(s) or directory")
    parser.add_argument("--sarif-out", help="Path to write SARIF v2.1.0 JSON report")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with non-zero code if findings exist")

    args = parser.parse_args()
    all_findings: Dict[str, List[Dict[str, Any]]] = {}

    target_files = []
    for t in args.targets:
        if os.path.isdir(t):
            for root, _, files in os.walk(t):
                for file in files:
                    if file.endswith((".sol", ".circom")):
                        target_files.append(os.path.join(root, file))
        elif os.path.isfile(t):
            target_files.append(t)

    total_issues = 0
    for target in target_files:
        scanner = StaticSecurityAuditor(target)
        findings = scanner.run()
        if findings:
            all_findings[target] = findings
            total_issues += len(findings)

    if args.sarif_out:
        sarif_json = build_sarif_log(all_findings)
        with open(args.sarif_out, "w", encoding="utf-8") as f:
            json.dump(sarif_json, f, indent=2)
        print(f"SARIF report written to {args.sarif_out} ({total_issues} issues found)")
    else:
        if not all_findings:
            print("No arithmetic or constraint violations detected.")
        else:
            for filepath, findings in all_findings.items():
                print(f"\n{'=' * 60}\n File: {filepath}\n{'=' * 60}")
                for f in findings:
                    print(
                        f"[{f['ruleId']}] [{f['severity']}] Line {f['line']}: {f['title']}\n"
                        f"  Snippet:     {f.get('snippet', 'N/A')}\n"
                        f"  Remediation: {f['remediation']}\n"
                    )

    if args.fail_on_findings and total_issues > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
