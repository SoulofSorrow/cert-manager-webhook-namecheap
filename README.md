# cert-manager-webhook-namecheap

A cert-manager ACME DNS-01 webhook solver for Namecheap DNS.
Enables wildcard certificates via Let's Encrypt without Helm.

## Requirements

- cert-manager installed (any method — Helm, manifests, k3s)
- Namecheap API access enabled (Profile → Tools → API Access)
- Your cluster's egress IP whitelisted in Namecheap API settings

## Namecheap API Limitations

- `namecheap.domains.dns.setHosts` replaces **all** DNS records atomically.
  The webhook reads existing records first and merges before writing.
- API access requires manual activation by Namecheap (not available for all accounts by default).
- Your whitelisted IP must match `clientIP` in the credentials secret exactly.

## Installation

### 1. Apply RBAC and Webhook

```bash
kubectl apply -f deploy/rbac/rbac.yaml
kubectl apply -f deploy/apiservice.yaml
kubectl apply -f deploy/deployment.yaml
```

### 2. Create Credentials Secret

Edit `deploy/secret.yaml` with your values, then:

```bash
kubectl apply -f deploy/secret.yaml
```

Find your cluster egress IP:
```bash
kubectl run egress-check --rm -it --image=alpine --restart=Never -- \
  wget -qO- https://api.ipify.org && echo
```

### 3. Create ClusterIssuer

Edit `deploy/clusterissuer.yaml` and set your email address, then:

```bash
kubectl apply -f deploy/clusterissuer.yaml
```

**Important:** Replace `acme.yourdomain.com` with your own group name in:
- `deploy/rbac/rbac.yaml`
- `deploy/apiservice.yaml`
- `deploy/deployment.yaml` (GROUP_NAME env var)
- `deploy/clusterissuer.yaml`

### 4. Request a Certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-wildcard
  namespace: default
spec:
  secretName: my-wildcard-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - "example.com"
    - "*.example.com"
```

## Configuration

Credentials can be provided two ways:

**Option A: Environment variables (simpler)**
Set in the Deployment directly or via a secret reference (already configured in `deploy/deployment.yaml`).

**Option B: Per-solver secret reference**
Specify in the ClusterIssuer solver config:
```yaml
config:
  secretName: namecheap-credentials
  secretNamespace: cert-manager
```

## Building

```bash
# Local build
make build

# Docker (multi-arch)
make docker-buildx IMAGE=ghcr.io/youruser/cert-manager-webhook-namecheap TAG=v1.0.0
```

## Troubleshooting

```bash
# Check webhook logs
kubectl logs -n cert-manager -l app=cert-manager-webhook-namecheap -f

# Check certificate status
kubectl describe certificate my-wildcard -n default

# Check ACME challenge status
kubectl get challenges -A
kubectl describe challenge <name> -n <namespace>

# Verify webhook is registered
kubectl get apiservice v1alpha1.acme.yourdomain.com
```

## Directory Structure

```
.
├── cmd/webhook/main.go          # Entrypoint
├── pkg/
│   ├── namecheap/client.go      # Namecheap API client
│   └── solver/solver.go         # cert-manager webhook interface
├── deploy/
│   ├── rbac/rbac.yaml           # ServiceAccount, ClusterRole, ClusterRoleBinding
│   ├── deployment.yaml          # Deployment + Service
│   ├── apiservice.yaml          # APIService + TLS Certificate
│   ├── clusterissuer.yaml       # ClusterIssuer examples
│   └── secret.yaml              # Credentials secret template
├── .github/workflows/build.yaml # CI/CD (multi-arch build + push to GHCR)
├── Dockerfile
├── Makefile
└── go.mod
```
