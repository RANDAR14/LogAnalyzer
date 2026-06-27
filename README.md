# 🔍 LogAnalyzer

PowerShell tool for analyzing Windows Security logs and detecting suspicious activity.

## 📌 Features
- Detects failed and successful logins (Event IDs 4625, 4624)
- Identifies new accounts, lockouts, and deleted accounts
- Detects privilege escalation events (Event ID 4672)
- Identifies brute force attacks (multiple failed logins from same source)
- Generates detailed text reports

## 🚀 How to Use
1. Open PowerShell as Administrator
2. Run:
   ```powershell
   .\LogAnalyzer.ps1
