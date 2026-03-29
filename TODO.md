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
- [x] Detect `lxc.apparmor.allow_nesting` / `allow_incomplete` / `raw` -- nested escape surface
- [x] Detect `lxc.seccomp.allow_nesting` -- privilege boundary weakened
- [x] Detect `lxc.cgroup.devices.allow = a` or broad patterns (`c 1:*`) -- raw device access
- [x] Detect missing resource limits: `lxc.cgroup.memory.limit_in_bytes`, `lxc.prlimit.nproc`
- [x] Detect missing `lxc.rootfs.options = ro` (read-only rootfs)

### MEDIUM
- [x] Enhance mount entry parsing to check OPTIONS (rbind, loop, remount), not just source paths
- [x] Parse `lxc.mount.fstab` referenced files for dangerous entries
- [x] Detect nested LXC (LXC-in-LXC) configurations

## Docker Scanner

### HIGH
- [x] Analyse daemon config (`/etc/docker/daemon.json`): `userns-remap`, `icc`
- [x] Detect container `Config.User` empty or root (root inside container, independent of systemd User=)
- [x] Detect missing resource limits: `Memory`, `PidsLimit`
- [x] Detect `RestartPolicy.Name = always` (persistence vector for compromised containers)
- [x] Detect `LogConfig.Type = none` (audit trail disabled)
- [x] Detect dangerous `DeviceCgroupRules` (e.g., `a *:* rwm` grants all device access)
- [x] Detect dangerous `Devices[]` array entries (`/dev/mem`, `/dev/kmem`, `/dev/fuse`, `/dev/net/tun`)

### MEDIUM
- [x] Detect Docker socket mount writable (check `ro` option on `/var/run/docker.sock` bind)
- [x] Detect `ExtraHosts` injection (custom /etc/hosts entries)
- [x] Detect `Ulimits` excessive values (file descriptor exhaustion)
- [x] Detect SELinux `label=type=spc_t` (super privileged container type)

## Podman Scanner

### HIGH
- [x] Check all 5 OCI capability sets: ambient, inheritable, permitted (now all 5 checked)
- [x] Validate `linux.maskedPaths` includes critical paths (`/proc/kcore`, `/proc/sysrq-trigger`, `/proc/mem`)
- [x] Validate `linux.readonlyPaths` includes `/proc/sys`, `/proc/irq`, `/sys/firmware`
- [x] Detect SELinux label issues: `process.selinuxLabel` with `spc_t`
- [x] Detect missing resource limits: `linux.resources.memory.limit`, `linux.resources.pids.limit`

### MEDIUM
- [x] Validate `linux.resources.devices` allowlist strictness (deny dangerous devices)
- [x] Check `rootfsPropagation` is not "shared"
- [x] Detect sensitive data in `process.env` (API keys, passwords, LD_PRELOAD)
- [x] Read `containers.conf` system/user defaults for baseline security settings

## Kubernetes Scanner

### CRITICAL
- [x] Scan kube-apiserver manifest: `--anonymous-auth`, `--insecure-port`, `--authorization-mode`, `--encryption-provider-config`, `--enable-admission-plugins`
- [x] Scan etcd manifest: client/peer TLS, at-rest encryption
- [x] Detect ClusterRoleBinding to `system:anonymous` / `system:unauthenticated`
- [x] Scan kube-controller-manager: `--service-account-private-key-file`, `--root-ca-file`, `--use-service-account-credentials`

### HIGH
- [x] Detect `imagePullPolicy: IfNotPresent` (supply chain risk)
- [x] Validate `spec.securityContext.sysctls` against unsafe sysctl list
- [x] Scan ValidatingWebhookConfiguration / MutatingWebhookConfiguration for `failurePolicy: Ignore`
- [x] Expand RBAC detection: impersonate verbs, configmaps/get, clusterrolebindings/create
- [x] Detect PodSecurityPolicy resources (deprecated API, should not be used)
- [x] Detect missing SELinux options in pod security context

### MEDIUM
- [x] Validate `fsGroup` in pod security context
- [x] Check liveness/readiness probe security (exec probes with arbitrary commands)
- [x] Validate volume types: NFS, iSCSI, flexVolume (implicit security properties)
- [x] Detect missing `ResourceQuota` / default-deny `NetworkPolicy` per namespace (post-scan cross-manifest analysis)
- [x] Scan `PersistentVolume` for hostPath PVs
- [x] Detect workload-specific risks (DaemonSet on all nodes, CronJob history limits)

### K3s/RKE2-specific
- [x] Validate `--write-kubeconfig` permissions
- [x] Check `--datastore-endpoint` for TLS/credentials
- [x] Scan `/var/lib/rancher/k3s/server/token` file permissions
- [x] Check `/etc/rancher/k3s/registries.yaml` for embedded secrets
- [x] Detect K3s bootstrap token rotation configuration
- [x] Validate K3s-specific `--kubelet-arg` and `--kube-apiserver-arg` flags (already implemented via control plane scanning: kube-apiserver-arg, kube-controller-manager-arg, and kubelet-arg are all parsed)

### API server audit logging
- [x] Detect missing `--audit-log-path` and `--audit-policy-file`
- [x] Validate audit log retention (maxage, maxbackup)
