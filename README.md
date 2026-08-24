# ⚡ BAY-SEC Static Security Auditor
### Binary Analysis & Yield — Secure Solutions (v1.2.0)

> Advanced static analysis engine for detecting EVM arithmetic precision flaws, ERC-4626 vault inflation vulnerabilities, and unconstrained Circom ZK circuit signals.

---

## 🛡️ Rule Coverage Matrix

| Rule ID | Severity | Category | Target | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ARITH-001` | **HIGH** | Precision Loss | Solidity / EVM | Detects division executed before multiplication causing integer truncation. |
| `ARITH-002` | **MEDIUM** | Rounding DoS | Solidity / EVM | Identifies strict `==` equality assertions on division results. |
| `ARITH-003` | **LOW** | Type Safety | Solidity / EVM | Flags unchecked integer downcasting without prior boundary guards. |
| `VAULT-001` | **HIGH** | Vault Inflation | ERC-4626 | Catches missing ceiling rounding on withdrawal/redeem share conversions. |
| `CIRCOM-001` | **CRITICAL** | Under-constrained | Circom / ZK | Detects witness assignments (`<--`) missing corresponding R1CS equality (`===`). |

---

## 🚀 Quick Start

### 1. Single File or Directory Scan
```bash
# Direct terminal output
python3 static_security_auditor.py ./contracts/Vault.sol

# Generate standard SARIF v2.1.0 output for CI/CD
python3 static_security_auditor.py ./src --sarif-out results.sarif --fail-on-findings
# Scan local directories (auto-ignores node_modules, lib, tests)
python3 batch_auditor.py --dirs ./src ./contracts --output-md triage.md

# Bulk scan remote repositories from a target list
python3 batch_auditor.py --repo-list targets.txt --output-md triage.md --output-sarif results.sarif
