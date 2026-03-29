# Scanner Improvement TODO

Findings from multi-agent security analysis (2026-03-29).
Each container runtime has unique security models -- do NOT apply a universal checklist.

## LXC Scanner

### CRITICAL
- [x] Detect `lxc.namespace.share.{net,ipc,pid,uts,mnt,user}` -- direct isolation bypass
- [x] Detect `lxc.namespace.keep` -- namespaces NOT isolated from host
- [x] Detect `lxc.mount.auto` dangerous options: `proc:rw`, `sys:rw`, `cgroup:rw`, `cgroup2:rw` -- cgroup escape vector
- [x] Detect missing/unconfined `lxc.selinux.context` (AppArmor is checked, SELinux is not)

### HIGH
- [ ] Detect `lxc.apparmor.allow_nesting` / `allow_incomplete` / `raw` -- nested escape surface
- [ ] Detect `lxc.seccomp.allow_nesting` -- privilege boundary weakened
- [ ] Detect `lxc.cgroup.devices.allow = a` or broad patterns (`c 1:*`) -- raw device access
- [ ] Detect missing resource limits: `lxc.cgroup.memory.limit_in_bytes`, `lxc.prlimit.nproc`, CPU limits
- [ ] Detect missing `lxc.rootfs.options = ro` (read-only rootfs)

### MEDIUM
- [ ] Enhance mount entry parsing to check OPTIONS (rbind, loop, remount), not just source paths
- [ ] Parse `lxc.mount.fstab` referenced files for dangerous entries
- [ ] Detect nested LXC (LXC-in-LXC) configurations

### LXC-specific notes
- LXC uses blacklist model (cap.drop) vs Docker's whitelist (CapAdd) -- different detection logic needed
- `lxc.mount.auto` is LXC-unique, no equivalent in Docker/Podman
- Config paths are unpredictable -- os.walk MUST be preserved

## Docker Scanner

### HIGH
- [x] Analyse daemon config (`/etc/docker/daemon.json`): `userns-remap`, `icc` (partial: iptables, no-new-privileges, default-ulimits, log-driver, seccomp-profile remaining)
- [x] Detect container `Config.User` empty or root (root inside container, independent of systemd User=)
- [x] Detect missing resource limits: `Memory`, `PidsLimit` (NanoCpus, CpuQuota, MemorySwap remaining)
- [x] Detect `RestartPolicy.Name = always` (persistence vector for compromised containers)
- [x] Detect `LogConfig.Type = none` (audit trail disabled)
- [ ] Detect dangerous `DeviceCgroupRules` (e.g., `a *:* rwm` grants all device access)
- [ ] Detect dangerous `Devices[]` array entries (`/dev/mem`, `/dev/kmem`, `/dev/fuse`, `/dev/net/tun`)

### MEDIUM
- [ ] Detect Docker socket mount writable (check `ro` option on `/var/run/docker.sock` bind)
- [ ] Detect `ExtraHosts` injection (custom /etc/hosts entries)
- [ ] Detect `Ulimits` excessive values (file descriptor exhaustion)
- [ ] Detect SELinux `label=type=spc_t` (super privileged container type)

## Podman Scanner

### HIGH
- [x] Check all 5 OCI capability sets: ambient, inheritable, permitted (now all 5 checked)
- [x] Validate `linux.maskedPaths` includes critical paths (`/proc/kcore`, `/proc/sysrq-trigger`, `/proc/mem`)
- [ ] Validate `linux.readonlyPaths` includes `/proc/sys`, `/proc/irq`, `/sys/firmware`
- [ ] Detect SELinux label issues: `process.selinuxLabel` with `spc_t` or missing on RHEL-based systems
- [x] Detect missing resource limits: `linux.resources.memory.limit`, `linux.resources.pids.limit` (cpu remaining)

### MEDIUM
- [ ] Validate `linux.resources.devices` allowlist strictness (deny dangerous devices)
- [ ] Check `rootfsPropagation` is not "shared"
- [ ] Detect sensitive data in `process.env` (API keys, passwords, LD_PRELOAD)
- [ ] Read `containers.conf` system/user defaults for baseline security settings

## Kubernetes Scanner

### CRITICAL
- [x] Scan kube-apiserver manifest: `--anonymous-auth`, `--insecure-port`, `--authorization-mode`, `--encryption-provider-config`, `--enable-admission-plugins`
- [x] Scan etcd manifest: client/peer TLS, at-rest encryption
- [x] Detect ClusterRoleBinding to `system:anonymous` / `system:unauthenticated`
- [x] Scan kube-controller-manager: `--service-account-private-key-file`, `--root-ca-file`, `--use-service-account-credentials`

### HIGH
- [ ] Detect `imagePullPolicy: IfNotPresent` (supply chain risk)
- [ ] Validate `spec.securityContext.sysctls` against unsafe sysctl list
- [ ] Scan ValidatingWebhookConfiguration / MutatingWebhookConfiguration for `failurePolicy: Ignore`
- [ ] Expand RBAC detection: impersonate verbs, configmaps/get, clusterrolebindings/create, watch secrets
- [ ] Detect PodSecurityPolicy resources and admission controller status
- [ ] Detect missing SELinux options in pod security context

### MEDIUM
- [ ] Validate `fsGroup` / `supplementalGroups` in pod security context
- [ ] Check liveness/readiness probe security (exec probes with arbitrary commands)
- [ ] Validate volume types: NFS, iSCSI, flexVolume (implicit security properties)
- [ ] Detect missing `ResourceQuota` / default-deny `NetworkPolicy` per namespace
- [ ] Scan `PersistentVolume` for hostPath PVs
- [ ] Detect workload-specific risks (DaemonSet on all nodes, CronJob history limits)

### K3s/RKE2-specific
- [ ] Validate `--write-kubeconfig` permissions
- [ ] Check `--datastore-endpoint` for TLS/credentials
- [ ] Scan `/var/lib/rancher/k3s/server/token` file permissions
- [ ] Check `/etc/rancher/k3s/registries.yaml` for embedded secrets
- [ ] Detect K3s bootstrap token rotation configuration
- [ ] Validate K3s-specific `--kubelet-arg` and `--kube-apiserver-arg` flags

### API server audit logging
- [ ] Detect missing `--audit-log-path` and `--audit-policy-file`
- [ ] Validate audit log retention (maxage, maxbackup)
