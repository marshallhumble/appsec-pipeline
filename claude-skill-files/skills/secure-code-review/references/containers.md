# Container Security

Containers extend the application attack surface into the build, registry, and
runtime layers. A secure application in an insecure container image or runtime
configuration is still exploitable.

Relevant for: ECS (Fargate and EC2), EKS, Azure AKS, and any Docker-based deployment.

---

## Dockerfile Security

### Run as Non-Root

Containers run as root by default. A process that escapes the container inherits
those privileges on the host.

```dockerfile
# CORRECT — create a non-root user and switch to it
FROM mcr.microsoft.com/dotnet/aspnet:8.0

RUN addgroup --system --gid 1001 appgroup && \
    adduser  --system --uid 1001 --ingroup appgroup appuser

WORKDIR /app
COPY --chown=appuser:appgroup ../../../../../../../../home/hexxonxonx/Downloads/files .

USER appuser
ENTRYPOINT ["dotnet", "MyApp.dll"]
```

```dockerfile
# Rust — multi-stage: build as root, run as non-root
FROM rust:1.77 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=builder /build/target/release/myapp /usr/local/bin/myapp
USER app
CMD ["myapp"]
```

```dockerfile
# Go — distroless: no shell, no package manager, minimal attack surface
FROM golang:1.22 AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -o myapp .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/myapp /myapp
USER nonroot:nonroot
ENTRYPOINT ["/myapp"]
```

### No Secrets in Images

Secrets baked into image layers persist even after `docker history` commands and
are exposed in any registry the image is pushed to.

```dockerfile
# NEVER — secret in ENV
ENV DB_PASSWORD=hunter2

# NEVER — secret in ARG (visible in docker history even if unset afterwards)
ARG API_KEY=sk-abc123
RUN configure --api-key=$API_KEY

# CORRECT — inject secrets at runtime via environment or secrets mount
# In ECS: reference Secrets Manager in task definition
# In Kubernetes: use Secrets or External Secrets Operator
# Docker run: docker run -e DB_PASSWORD="$(aws secretsmanager get-secret-value ...)" myapp
```

If a secret was ever committed in a Dockerfile or baked into an image layer, rotate
the credential — the image may already be in a registry.

### Keep Images Small and Patched

```dockerfile
# Use multi-stage builds — final image contains only runtime artefacts
# Use distroless or slim base images — fewer packages = smaller attack surface
# Pin base image to digest, not just tag
FROM mcr.microsoft.com/dotnet/aspnet:8.0@sha256:abc123...

# Update base image packages in CI regularly
# Run trivy or grype against built images in CI
```

### Read-Only Filesystem

```dockerfile
# Where possible, make the container filesystem read-only at runtime
# ECS task definition:
# "readonlyRootFilesystem": true
# If the app needs to write, mount a specific volume for that path only
```

---

## Secrets at Runtime

### ECS (Fargate/EC2)

Inject secrets via Secrets Manager or SSM Parameter Store references in the task
definition. Values are injected as environment variables at container start; never
stored in the image or task definition plaintext.

```json
{
  "containerDefinitions": [{
    "name": "myapp",
    "secrets": [
      {
        "name": "DB_PASSWORD",
        "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password"
      },
      {
        "name": "API_KEY",
        "valueFrom": "/prod/app/api-key"
      }
    ]
  }]
}
```

The task execution role needs `secretsmanager:GetSecretValue` and/or
`ssm:GetParameters` permissions scoped to the specific secret ARNs.

### Kubernetes / AKS

```yaml
# External Secrets Operator (preferred — syncs from AWS Secrets Manager or Key Vault)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-secret
spec:
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: db-secret
  data:
    - secretKey: password
      remoteRef:
        key: prod/db/password
        property: password
---
# Reference in Pod spec
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-secret
        key: password
```

Avoid Kubernetes native Secrets for sensitive credentials without envelope
encryption — they are base64-encoded (not encrypted) at rest by default unless
you configure KMS envelope encryption for etcd.

---

## Runtime Security Controls

### Resource Limits

```json
// ECS task definition — always set CPU and memory limits
{
  "cpu": "256",
  "memory": "512",
  "memoryReservation": "256"
}
```

Without limits, a container can exhaust host resources — causing noisy-neighbour
DoS or enabling resource exhaustion attacks.

### Capabilities

```yaml
# Kubernetes — drop all capabilities, add back only what's needed
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]   # only if binding to port < 1024
  runAsNonRoot: true
  runAsUser: 1001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
```

### Network Policy (Kubernetes)

```yaml
# Default-deny all ingress and egress, then explicitly allow
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

---

## Image Scanning

Scan images in CI before pushing to registry, and again in the registry continuously.

```bash
# Scan a built image
trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:latest

# Scan in CI (GitHub Actions)
- name: Scan image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myapp:${{ github.sha }}
    severity: HIGH,CRITICAL
    exit-code: 1

# AWS ECR — enable automatic scanning
aws ecr put-image-scanning-configuration \
    --repository-name myapp \
    --image-scanning-configuration scanOnPush=true

# Azure ACR — enable Microsoft Defender for Containers
az acr update --name myregistry \
    --resource-group my-rg \
    --sku Premium
# Then enable Defender for Containers in Defender for Cloud
```

---

## Container Security Checklist

- [ ] All containers run as non-root user
- [ ] Multi-stage builds used; final image is slim or distroless
- [ ] Base image pinned to digest, not mutable tag
- [ ] No secrets in ENV, ARG, or any image layer
- [ ] Secrets injected at runtime via Secrets Manager / Key Vault / External Secrets
- [ ] CPU and memory limits set on all containers
- [ ] `readOnlyRootFilesystem: true` where possible
- [ ] All capabilities dropped; only required ones added back
- [ ] Image scanned with trivy or grype in CI; scan on push to registry enabled
- [ ] Network policies restrict inter-service traffic to what is required
- [ ] ECR/ACR repository access restricted; no anonymous pull
- [ ] Task/pod execution role follows least privilege
