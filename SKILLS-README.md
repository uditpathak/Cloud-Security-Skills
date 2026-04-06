# Cloud Pentest Claude Code Skills

Three offensive Claude Code skills for cloud penetration testing.
Designed to be shared alongside blog posts as free companion tools.

## Skills Included

### 1. cloud-recon
**Phase:** Reconnaissance
**What it does:** Generates structured recon plans for discovering cloud attack surfaces. Covers external passive recon (storage buckets, subdomains, credential leaks), active recon (port scanning, API discovery, metadata probing), and gray box enumeration.
**Includes:** AWS and Azure reference files with detailed enumeration commands.

### 2. cloud-exploit-mapper
**Phase:** Attack Path Mapping
**What it does:** Takes recon findings and maps them to exploitable attack paths. Identifies privilege escalation routes, maps to MITRE ATT&CK Cloud techniques, and prioritizes paths by impact/difficulty/noise.
**Covers:** 10 AWS and 7 Azure privilege escalation paths with detailed conditions.

### 3. cloud-exploit-guide
**Phase:** Exploitation
**What it does:** Provides exact commands to exploit identified vulnerabilities. Step-by-step PACU modules, AWS CLI, Azure CLI commands for privilege escalation, credential extraction, lateral movement, and persistence.
**Covers:** Full kill chain from escalation through persistence with evidence collection.

## Installation (Claude Code)
Copy each skill folder into your Claude Code skills directory.

## Usage Flow
Recon (cloud-recon) → Map (cloud-exploit-mapper) → Exploit (cloud-exploit-guide)

## Author
Udit Pathak
