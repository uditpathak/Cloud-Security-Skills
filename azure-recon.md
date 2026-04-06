# Azure Reconnaissance Reference

Detailed Azure enumeration commands for gray box engagements.

## Entra ID (Azure AD) Enumeration

```bash
# Current user info
az ad signed-in-user show

# List all users
az ad user list --output table

# List all groups
az ad group list --output table

# List group members
az ad group member list --group {group-id} --output table

# List all service principals (app registrations)
az ad sp list --all --output table

# Check role assignments (who has what access)
az role assignment list --all --output table

# List Global Admins
az role assignment list --role "Global Administrator" --output table

# List custom roles (may have dangerous permissions)
az role definition list --custom-role-only true --output table
```

## ROADtools Enumeration

```bash
# Authenticate
roadrecon auth -u {user} -p {password}
# Or with access token
roadrecon auth --access-token {token}

# Gather all data
roadrecon gather

# Launch interactive explorer
roadrecon gui
```

## Storage Account Enumeration

```bash
# List storage accounts
az storage account list --output table

# List containers in a storage account
az storage container list --account-name {name} --output table

# Check container access level (blob = anonymous blob read, container = anonymous list+read)
az storage container show --name {container} --account-name {name} --query 'properties.publicAccess'

# List blobs
az storage blob list --container-name {container} --account-name {name} --output table

# List storage account keys (if you have permission, this bypasses all RBAC)
az storage account keys list --account-name {name}

# Check SAS token policies
az storage account show --name {name} --query 'allowSharedKeyAccess'
```

## Virtual Machine Enumeration

```bash
# List all VMs
az vm list --output table

# Show VM details including managed identity
az vm show --name {vm-name} --resource-group {rg} --query '[name,identity]'

# List NSG rules
az network nsg list --output table
az network nsg rule list --nsg-name {nsg} --resource-group {rg} --output table

# Check for open ports to internet
az network nsg rule list --nsg-name {nsg} --resource-group {rg} --query "[?sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet']" --output table

# Check VM extensions (may reveal configs)
az vm extension list --vm-name {name} --resource-group {rg}

# Get VM user data
az vm show --name {vm-name} --resource-group {rg} --query 'userData' --output tsv | base64 -d
```

## App Service Enumeration

```bash
# List App Services
az webapp list --output table

# Show app settings (may contain secrets)
az webapp config appsettings list --name {app} --resource-group {rg}

# Check managed identity
az webapp identity show --name {app} --resource-group {rg}

# Check authentication settings
az webapp auth show --name {app} --resource-group {rg}

# List deployment slots
az webapp deployment slot list --name {app} --resource-group {rg}

# Check SCM/Kudu access
curl -s https://{app}.scm.azurewebsites.net/
```

## Key Vault Enumeration

```bash
# List Key Vaults
az keyvault list --output table

# List secrets in a vault
az keyvault secret list --vault-name {vault} --output table

# Get a secret value
az keyvault secret show --vault-name {vault} --name {secret-name}

# List keys
az keyvault key list --vault-name {vault} --output table

# List certificates
az keyvault certificate list --vault-name {vault} --output table

# Check access policies
az keyvault show --name {vault} --query 'properties.accessPolicies'
```

## Azure SQL Enumeration

```bash
# List SQL servers
az sql server list --output table

# List databases
az sql db list --server {server} --resource-group {rg} --output table

# Check firewall rules (0.0.0.0 means allow all Azure services)
az sql server firewall-rule list --server {server} --resource-group {rg} --output table

# Check if AD auth is configured
az sql server ad-admin list --server {server} --resource-group {rg}
```

## Activity Logs (Detection Posture)

```bash
# Check diagnostic settings
az monitor diagnostic-settings list --resource {resource-id}

# Check activity log alerts
az monitor activity-log alert list --output table

# Check Log Analytics workspaces
az monitor log-analytics workspace list --output table
```

## Automation Accounts

```bash
# List automation accounts (often have high-privilege credentials)
az automation account list --output table

# List runbooks
az automation runbook list --automation-account-name {name} --resource-group {rg} --output table
```

## Azure-Specific Tools

```powershell
# MicroBurst - Azure pentest toolkit
Import-Module MicroBurst.psm1

# Enumerate Azure subdomains
Invoke-EnumerateAzureSubDomains -Base {company}

# Get Azure domains
Get-AzDomainInfo -folder output

# AzureHound for BloodHound
azurehound -u {user} -p {password} list --tenant {tenant-id} -o output.json
```
