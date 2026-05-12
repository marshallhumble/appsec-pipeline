# Azure Security Patterns

Load when the question involves Azure infrastructure, services, RBAC, Key Vault,
Managed Identity, or deployment. Load alongside `references/lang/<lang>.md` for
SDK usage in a specific language.

---

## Managed Identity — No Credentials in Code

Managed Identity is the Azure equivalent of AWS IAM instance roles. It provides
an automatically rotated credential to Azure compute resources. Use it everywhere
instead of storing credentials.

```csharp
// DefaultAzureCredential tries: Managed Identity → environment → VS credential chain
// In Azure (App Service, AKS, Functions): uses Managed Identity automatically
// Locally: falls back to az login credentials
using Azure.Identity;

var credential = new DefaultAzureCredential();

// Key Vault
var kvClient = new SecretClient(
    new Uri("https://my-vault.vault.azure.net/"),
    credential);

// Storage
var blobClient = new BlobServiceClient(
    new Uri("https://myaccount.blob.core.windows.net/"),
    credential);

// Never: StorageSharedKeyCredential with hardcoded account key
// Never: connection strings with AccountKey= in config
```

```bash
# Verify which identity is in use
az account show
az identity show --ids /subscriptions/.../resourceGroups/.../providers/Microsoft.ManagedIdentity/...
```

---

## Key Vault

```bash
# Create vault with RBAC authorization model (preferred over access policies)
az keyvault create \
    --name my-vault \
    --resource-group my-rg \
    --enable-rbac-authorization true \
    --soft-delete-retention-days 90

# Store a secret
az keyvault secret set \
    --vault-name my-vault \
    --name "db-password" \
    --value "$(openssl rand -base64 32)"

# Grant an app's Managed Identity read access via RBAC
az role assignment create \
    --role "Key Vault Secrets User" \
    --assignee <managed-identity-object-id> \
    --scope /subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/my-vault

# Retrieve in scripts
DB_PASSWORD=$(az keyvault secret show \
    --vault-name my-vault \
    --name db-password \
    --query value -o tsv)
```

```csharp
// Load Key Vault into IConfiguration (all secrets accessible by name)
builder.Configuration.AddAzureKeyVault(
    new Uri(builder.Configuration["KeyVaultUri"]!),
    new DefaultAzureCredential());

// Access like any config value
var dbPassword = builder.Configuration["db-password"];
```

**Key rotation:**
```bash
# Enable automatic rotation via Event Grid + Azure Functions
# Or use Key Vault's built-in rotation policy for certificates
az keyvault certificate set-policy --vault-name my-vault --name my-cert \
    --validity-in-months 12
```

---

## Azure RBAC — Least Privilege

```bash
# NEVER — Owner or Contributor on a production subscription for app identities
# NEVER — long-lived service principal secrets in code or config

# ALWAYS — assign the minimum built-in role at the narrowest scope
# Reader: read-only access
# Storage Blob Data Reader: read blobs only (not manage the account)
# Key Vault Secrets User: read secrets only

az role assignment create \
    --role "Storage Blob Data Reader" \
    --assignee <managed-identity-object-id> \
    --scope /subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/myaccount/blobServices/default/containers/mycontainer

# Audit role assignments
az role assignment list --all --output table

# Use PIM (Privileged Identity Management) for time-limited admin access
# Require justification + approval + MFA for privileged role activation
```

---

## App Service / Azure Functions Security

```bash
# ALWAYS — use Managed Identity for outbound connections
az webapp identity assign --name my-app --resource-group my-rg

# ALWAYS — use Key Vault references in app settings instead of plaintext secrets
# Format: @Microsoft.KeyVault(SecretUri=https://my-vault.vault.azure.net/secrets/db-password/)
az webapp config appsettings set \
    --name my-app --resource-group my-rg \
    --settings "DB_PASSWORD=@Microsoft.KeyVault(SecretUri=https://my-vault.vault.azure.net/secrets/db-password/)"

# ALWAYS — enforce HTTPS only
az webapp update --name my-app --resource-group my-rg --https-only true

# ALWAYS — disable FTP (use deployment slots or Azure DevOps)
az webapp config set --name my-app --resource-group my-rg \
    --ftps-state Disabled

# ALWAYS — set minimum TLS version
az webapp config set --name my-app --resource-group my-rg \
    --min-tls-version 1.2
```

---

## Storage Security

```bash
# ALWAYS — disable public blob access at account level
az storage account update \
    --name myaccount \
    --resource-group my-rg \
    --allow-blob-public-access false

# ALWAYS — enable secure transfer required (HTTPS only)
az storage account update \
    --name myaccount \
    --resource-group my-rg \
    --https-only true

# ALWAYS — use customer-managed keys for sensitive data
# (otherwise Azure uses Microsoft-managed keys)

# SAS tokens — scope tightly, set short expiry
az storage blob generate-sas \
    --account-name myaccount \
    --container-name mycontainer \
    --name myblob \
    --permissions r \
    --expiry $(date -u -d "1 hour" '+%Y-%m-%dT%H:%MZ')
```

---

## AKS / Container Security

```bash
# ALWAYS — use Workload Identity (OIDC federation) instead of mounting service
# principal secrets as environment variables
az aks update --name my-cluster --resource-group my-rg \
    --enable-oidc-issuer \
    --enable-workload-identity

# ALWAYS — enable Azure Policy add-on for pod security standards
az aks enable-addons --name my-cluster --resource-group my-rg \
    --addons azure-policy

# ALWAYS — private cluster (no public API endpoint)
az aks create --name my-cluster --resource-group my-rg \
    --enable-private-cluster

# Container images: store in ACR with vulnerability scanning
az acr create --name myregistry --resource-group my-rg \
    --sku Premium
az acr update --name myregistry --anonymous-pull-enabled false
```

---

## Azure Monitor & Defender

```bash
# ALWAYS — enable Microsoft Defender for Cloud on all subscriptions
az security pricing create \
    --name VirtualMachines --tier Standard
az security pricing create \
    --name SqlServers --tier Standard
az security pricing create \
    --name AppServices --tier Standard

# ALWAYS — enable diagnostic settings → Log Analytics for audit events
az monitor diagnostic-settings create \
    --name send-to-law \
    --resource /subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/my-vault \
    --workspace /subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/my-law \
    --logs '[{"category":"AuditEvent","enabled":true}]'

# Key events to alert on:
# - Key Vault: SecretGet, SecretSet from unexpected sources
# - RBAC: RoleAssignmentCreate at subscription scope
# - AAD: Sign-ins from unfamiliar locations; privileged role activations
# - Storage: public access enabled
```

---

## Service Principals vs Managed Identity

```bash
# Managed Identity (PREFERRED): no credential to manage, rotate, or leak
# Use for: App Service, Functions, VMs, AKS workloads, Logic Apps

# Service Principal (when Managed Identity isn't available):
# - Use certificate auth, not client secret, where possible
# - Certificate-based SP
az ad sp create-for-rbac \
    --name my-sp \
    --role "Contributor" \
    --scopes /subscriptions/.../resourceGroups/my-rg \
    --create-cert \
    --cert @my-cert.pem

# Rotate service principal secrets/certificates before expiry
# Alert on expiry via Azure AD notifications or custom automation
```

---

## Azure Security Checklist

- [ ] All Azure compute uses Managed Identity; no service principal secrets in code
- [ ] Key Vault used for all secrets; Key Vault references in App Service settings
- [ ] RBAC assignments follow least privilege; no Owner/Contributor for app identities
- [ ] Storage accounts: public blob access disabled, HTTPS-only, secure transfer required
- [ ] App Services: HTTPS-only, FTP disabled, minimum TLS 1.2
- [ ] Microsoft Defender for Cloud enabled and Standard tier on key services
- [ ] Diagnostic settings routing audit logs to Log Analytics
- [ ] PIM configured for privileged roles (time-limited, approval-gated)
- [ ] AKS: Workload Identity enabled, private cluster, Azure Policy add-on
- [ ] Container images scanned in ACR before deployment
