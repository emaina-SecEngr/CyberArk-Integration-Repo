# CyberArk Integration Repo

This repository contains reference scripts and learning materials for CyberArk integrations.

## Scripts

- `scripts/cyberark_ad_account_onboarding.ps1`
  - PowerShell example for integrating CyberArk with Active Directory
  - Demonstrates:
    - querying AD users
    - authenticating to CyberArk PVWA API
    - onboarding accounts into CyberArk
    - secure engineering concepts

## Security Notes

- Do not commit real passwords, tokens, or internal production URLs.
- Use placeholders for sensitive values.
- Validate platform IDs and API paths in your own environment.
