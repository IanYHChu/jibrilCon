"""Integration tests for the Kubernetes scanner module."""

from pathlib import Path

import pytest

from jibrilcon.scanners import kubernetes
from tests.conftest import _FAKE_SYSTEMD, _make_context, _write_binary

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _write_yaml(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _make_rootfs(tmp_path: Path) -> Path:
    """Create a minimal rootfs with systemd init."""
    _write_binary(tmp_path / "sbin" / "init", _FAKE_SYSTEMD)
    return tmp_path


# ------------------------------------------------------------------ #
# kubeadm static pod manifests
# ------------------------------------------------------------------ #


class TestKubeadmStaticPods:
    def test_clean_pod(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "clean.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: clean-pod
spec:
  automountServiceAccountToken: false
  securityContext:
    fsGroup: 1000
    seLinuxOptions:
      type: container_t
  containers:
  - name: app
    image: myapp:v1.0.0
    imagePullPolicy: Always
    securityContext:
      privileged: false
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["scanner"] == "kubernetes"
        assert result["summary"]["kubernetes_scanned"] == 1
        assert result["results"][0]["status"] == "clean"
        assert result["results"][0]["violations"] == []
        assert result["results"][0]["managed"] is True

    def test_privileged_pod(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "priv.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "privileged" in vio_ids
        assert containers[0]["status"] == "violated"

    def test_host_namespaces(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "host-ns.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: host-ns-pod
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_pid_namespace" in vio_ids
        assert "host_network_namespace" in vio_ids
        assert "host_ipc_namespace" in vio_ids

    def test_dangerous_capabilities(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "caps.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: caps-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      capabilities:
        add: ["SYS_ADMIN", "NET_RAW"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_capabilities_added" in vio_ids

    def test_dangerous_capabilities_lowercase(self, tmp_path):
        """Lowercase capability names must be detected as dangerous."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "lower.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: lower-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      capabilities:
        add: ["sys_admin"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_capabilities_added" in vio_ids

    def test_cap_drop_all_with_cap_prefix(self, tmp_path):
        """CAP_ALL in drop list must be normalised to ALL."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "drop.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: drop-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      capabilities:
        drop: ["CAP_ALL"]
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      runAsNonRoot: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cap_drop_all_missing" not in vio_ids


# ------------------------------------------------------------------ #
# K3s manifests
# ------------------------------------------------------------------ #


class TestK3sManifests:
    def test_k3s_auto_deploy_deployment(self, tmp_path):
        root = _make_rootfs(tmp_path)
        # Create K3s detection hint
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root
            / "var"
            / "lib"
            / "rancher"
            / "k3s"
            / "server"
            / "manifests"
            / "app.yaml",
            """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25
        securityContext:
          privileged: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["summary"]["kubernetes_scanned"] >= 1
        assert any(
            r["kind"] == "Deployment" and r["resource"] == "web-app"
            for r in result["results"]
        )
        vio_ids = [
            v["id"]
            for r in result["results"]
            if r["resource"] == "web-app"
            for v in r["violations"]
        ]
        assert "privileged" in vio_ids

    def test_k3s_static_pod(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root
            / "var"
            / "lib"
            / "rancher"
            / "k3s"
            / "agent"
            / "pod-manifests"
            / "mon.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: monitor
spec:
  hostNetwork: true
  containers:
  - name: agent
    image: monitor:v2
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "host_network_namespace" in vio_ids


# ------------------------------------------------------------------ #
# RKE2 manifests
# ------------------------------------------------------------------ #


class TestRKE2Manifests:
    def test_rke2_control_plane_static_pod(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "rke2").mkdir(parents=True)
        _write_yaml(
            root
            / "var"
            / "lib"
            / "rancher"
            / "rke2"
            / "agent"
            / "pod-manifests"
            / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  hostNetwork: true
  containers:
  - name: kube-apiserver
    image: rancher/hardened-kubernetes:v1.28.4
    securityContext:
      privileged: false
      runAsNonRoot: true
      runAsUser: 65534
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
    volumeMounts:
    - name: k8s-certs
      mountPath: /etc/kubernetes/pki
      readOnly: true
  volumes:
  - name: k8s-certs
    hostPath:
      path: /etc/kubernetes/pki
      type: DirectoryOrCreate
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["summary"]["kubernetes_scanned"] >= 1
        # hostNetwork is expected for kube-apiserver, but it's still flagged
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "host_network_namespace" in vio_ids


# ------------------------------------------------------------------ #
# Multi-document YAML
# ------------------------------------------------------------------ #


class TestMultiDocYAML:
    def test_multi_document_yaml(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "multi.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: pod-a
spec:
  containers:
  - name: a
    image: app-a:v1
    securityContext:
      privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-b
spec:
  automountServiceAccountToken: false
  securityContext:
    fsGroup: 1000
    seLinuxOptions:
      type: container_t
  containers:
  - name: b
    image: app-b:v1
    imagePullPolicy: Always
    securityContext:
      privileged: false
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        cpu: "100m"
        memory: "64Mi"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["summary"]["kubernetes_scanned"] == 2
        by_resource = {r["resource"]: r for r in result["results"]}
        assert by_resource["pod-a"]["status"] == "violated"
        assert by_resource["pod-b"]["status"] == "clean"


# ------------------------------------------------------------------ #
# hostPath volumes
# ------------------------------------------------------------------ #


class TestHostPathVolumes:
    def test_dangerous_hostpath_docker_sock(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "dind.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: dind-pod
spec:
  containers:
  - name: docker
    image: docker:24-dind
    volumeMounts:
    - name: docker-sock
      mountPath: /var/run/docker.sock
  volumes:
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
      type: Socket
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "hostpath_dangerous" in vio_ids

    def test_hostpath_not_readonly(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "rw-mount.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: rw-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    hostPath:
      path: /opt/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "hostpath_not_readonly" in vio_ids

    def test_hostpath_readonly_is_clean(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ro-mount.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: ro-pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:v1
    imagePullPolicy: Always
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        cpu: "100m"
        memory: "64Mi"
    volumeMounts:
    - name: data
      mountPath: /data
      readOnly: true
  volumes:
  - name: data
    hostPath:
      path: /opt/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "hostpath_not_readonly" not in vio_ids


# ------------------------------------------------------------------ #
# initContainers
# ------------------------------------------------------------------ #


class TestInitContainers:
    def test_init_container_scanned(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "init.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: init-pod
spec:
  initContainers:
  - name: setup
    image: busybox
    securityContext:
      privileged: true
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      privileged: false
      runAsNonRoot: true
      runAsUser: 1000
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        # Both init and regular container should be scanned
        assert result["summary"]["kubernetes_scanned"] == 2
        init_results = [
            r for r in result["results"] if r["container"].startswith("init:")
        ]
        assert len(init_results) == 1
        vio_ids = [v["id"] for v in init_results[0]["violations"]]
        assert "privileged" in vio_ids


# ------------------------------------------------------------------ #
# CronJob (deep nesting)
# ------------------------------------------------------------------ #


class TestCronJob:
    def test_cronjob_pod_spec_extracted(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "cron.yaml",
            """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleaner
            image: busybox
            securityContext:
              privileged: true
          restartPolicy: OnFailure
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["summary"]["kubernetes_scanned"] >= 1
        assert any(r["kind"] == "CronJob" for r in result["results"])
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "privileged" in vio_ids


# ------------------------------------------------------------------ #
# Violation enrichment
# ------------------------------------------------------------------ #


class TestViolationEnrichment:
    def test_violation_has_enriched_fields_and_no_internals(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "enriched.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: enriched-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        priv = [
            v for v in result["results"][0]["violations"] if v["id"] == "privileged"
        ][0]

        # Enriched fields present
        assert "severity" in priv
        assert isinstance(priv["severity"], (int, float))
        assert "risk" in priv
        assert "remediation" in priv
        assert "references" in priv
        assert "mitre_attack" in priv["references"]
        assert "cis_kubernetes_benchmark" in priv["references"]

        # Engine internals stripped
        assert "conditions" not in priv
        assert "logic" not in priv

        # Source path present
        assert "source" in priv
        assert priv["source"].startswith("/")


# ------------------------------------------------------------------ #
# Edge cases
# ------------------------------------------------------------------ #


class TestEdgeCases:
    def test_no_manifests_returns_empty(self, tmp_path):
        root = _make_rootfs(tmp_path)
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["scanner"] == "kubernetes"
        assert result["summary"]["kubernetes_scanned"] == 0
        assert result["results"] == []

    def test_non_workload_resource_skipped(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "service.yaml",
            """\
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  selector:
    app: web
  ports:
  - port: 80
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["summary"]["kubernetes_scanned"] == 0

    def test_empty_yaml_document(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "empty.yaml",
            """\
---
---
apiVersion: v1
kind: Pod
metadata:
  name: after-empty
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      privileged: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert result["summary"]["kubernetes_scanned"] >= 1

    def test_invalid_yaml_skipped(self, tmp_path):
        root = _make_rootfs(tmp_path)
        manifest_dir = root / "etc" / "kubernetes" / "manifests"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        (manifest_dir / "bad.yaml").write_text(
            "{{invalid yaml content", encoding="utf-8"
        )
        _write_yaml(
            manifest_dir / "good.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        # Good pod should still be scanned despite bad YAML
        assert result["summary"]["kubernetes_scanned"] >= 1

    def test_context_required(self, tmp_path):
        root = _make_rootfs(tmp_path)
        with pytest.raises(ValueError, match="ScanContext"):
            kubernetes.scan(str(root), context=None)

    def test_resource_limits_warning(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-limits.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: no-limits-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "no_resource_limits" in vio_ids

    def test_automount_sa_token_warning(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sa.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: sa-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        # Default automountServiceAccountToken is true
        assert "automount_sa_token" in vio_ids

    def test_hostport_warning(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "hostport.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: hostport-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    ports:
    - containerPort: 8080
      hostPort: 8080
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "host_port_used" in vio_ids

    def test_seccomp_unconfined(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "seccomp.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: seccomp-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      seccompProfile:
        type: Unconfined
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "seccomp_unconfined" in vio_ids

    def test_daemonset_scanned(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ds.yaml",
            """\
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: log-collector
spec:
  selector:
    matchLabels:
      app: logs
  template:
    metadata:
      labels:
        app: logs
    spec:
      containers:
      - name: collector
        image: fluentd:v1.16
        securityContext:
          privileged: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        assert any(r["kind"] == "DaemonSet" for r in result["results"])
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "privileged" in vio_ids


# ------------------------------------------------------------------ #
# mountPropagation: Bidirectional
# ------------------------------------------------------------------ #


class TestMountPropagation:
    def test_bidirectional_mount_propagation(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "bidir.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: bidir-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: data
      mountPath: /data
      mountPropagation: Bidirectional
  volumes:
  - name: data
    hostPath:
      path: /opt/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "mount_propagation_bidirectional" in vio_ids

    def test_host_to_container_propagation_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "h2c.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: h2c-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: data
      mountPath: /data
      mountPropagation: HostToContainer
      readOnly: true
  volumes:
  - name: data
    hostPath:
      path: /opt/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "mount_propagation_bidirectional" not in vio_ids


# ------------------------------------------------------------------ #
# Image tag checks
# ------------------------------------------------------------------ #


class TestImageTag:
    def test_image_latest_tag(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "latest.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: latest-pod
spec:
  containers:
  - name: app
    image: myapp:latest
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_tag_missing" in vio_ids

    def test_image_no_tag(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "notag.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: notag-pod
spec:
  containers:
  - name: app
    image: myapp
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_tag_missing" in vio_ids

    def test_image_with_digest_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "digest.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: digest-pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:v1.0@sha256:abcdef1234567890
    imagePullPolicy: Always
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        cpu: "100m"
        memory: "64Mi"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_tag_missing" not in vio_ids

    def test_image_specific_tag_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "tagged.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: tagged-pod
spec:
  containers:
  - name: app
    image: nginx:1.25.3
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_tag_missing" not in vio_ids


# ------------------------------------------------------------------ #
# AppArmor unconfined
# ------------------------------------------------------------------ #


class TestAppArmor:
    def test_apparmor_unconfined_field(self, tmp_path):
        """K8s 1.30+ appArmorProfile field."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "aa-field.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: aa-field-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      appArmorProfile:
        type: Unconfined
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "apparmor_unconfined" in vio_ids

    def test_apparmor_unconfined_annotation(self, tmp_path):
        """Pre-1.30 annotation-based AppArmor."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "aa-anno.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: aa-anno-pod
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: unconfined
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "apparmor_unconfined" in vio_ids

    def test_apparmor_runtime_default_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "aa-ok.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: aa-ok-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      appArmorProfile:
        type: RuntimeDefault
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "apparmor_unconfined" not in vio_ids

    def test_apparmor_annotation_on_deployment(self, tmp_path):
        """Annotation on pod template metadata in a Deployment."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "aa-deploy.yaml",
            """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aa-deploy
spec:
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
      annotations:
        container.apparmor.security.beta.kubernetes.io/web: unconfined
    spec:
      containers:
      - name: web
        image: nginx:1.25
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "apparmor_unconfined" in vio_ids


# ------------------------------------------------------------------ #
# procMount: Unmasked
# ------------------------------------------------------------------ #


class TestProcMount:
    def test_proc_mount_unmasked(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "procmount.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: procmount-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      procMount: Unmasked
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "proc_mount_unmasked" in vio_ids

    def test_proc_mount_default_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "procmount-ok.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: procmount-ok-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      procMount: Default
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "proc_mount_unmasked" not in vio_ids


# ------------------------------------------------------------------ #
# subPath with hostPath
# ------------------------------------------------------------------ #


class TestSubPathHostPath:
    def test_subpath_with_hostpath(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "subpath.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: subpath-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: host-vol
      mountPath: /data
      subPath: mydir
  volumes:
  - name: host-vol
    hostPath:
      path: /opt/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "subpath_with_hostpath" in vio_ids

    def test_subpathexpr_with_hostpath(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "subpathexpr.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: subpathexpr-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: host-vol
      mountPath: /data
      subPathExpr: $(POD_NAME)
  volumes:
  - name: host-vol
    hostPath:
      path: /opt/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "subpath_with_hostpath" in vio_ids

    def test_subpath_with_emptydir_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "subpath-empty.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: subpath-empty-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: cache
      mountPath: /cache
      subPath: mydir
  volumes:
  - name: cache
    emptyDir: {}
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "subpath_with_hostpath" not in vio_ids


# ------------------------------------------------------------------ #
# shareProcessNamespace
# ------------------------------------------------------------------ #


class TestShareProcessNamespace:
    def test_share_process_namespace(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sharens.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: sharens-pod
spec:
  shareProcessNamespace: true
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "share_process_namespace" in vio_ids

    def test_share_process_namespace_false_not_flagged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-sharens.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: no-sharens-pod
spec:
  shareProcessNamespace: false
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "share_process_namespace" not in vio_ids


# ------------------------------------------------------------------ #
# imagePullPolicy
# ------------------------------------------------------------------ #


class TestImagePullPolicy:
    def test_image_pull_not_always(self, tmp_path):
        """imagePullPolicy: IfNotPresent should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "cached.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: cached-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0
    imagePullPolicy: IfNotPresent
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_pull_not_always" in vio_ids

    def test_image_pull_never(self, tmp_path):
        """imagePullPolicy: Never should also trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "never.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: never-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0
    imagePullPolicy: Never
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_pull_not_always" in vio_ids

    def test_image_pull_no_policy_with_tag(self, tmp_path):
        """No explicit imagePullPolicy with a tagged image triggers warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "nopolicy.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: nopolicy-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_pull_not_always" in vio_ids

    def test_image_pull_always_not_flagged(self, tmp_path):
        """imagePullPolicy: Always should not trigger the warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "always.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: always-pod
spec:
  containers:
  - name: app
    image: myapp:v1.0
    imagePullPolicy: Always
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "image_pull_not_always" not in vio_ids

    def test_image_pull_latest_no_policy_not_flagged(self, tmp_path):
        """:latest with no policy should NOT trigger image_pull_not_always.

        K8s defaults to Always for :latest images, so the risk is different.
        The image_tag_missing rule already covers this case.
        """
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "latest-nopol.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: latest-nopol-pod
spec:
  containers:
  - name: app
    image: myapp:latest
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        # image_tag_missing fires, but image_pull_not_always should NOT
        assert "image_tag_missing" in vio_ids
        assert "image_pull_not_always" not in vio_ids


# ================================================================== #
# Phase 2: RBAC scanning
# ================================================================== #


class TestRBACWildcards:
    def test_wildcard_verbs(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "role-wild.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-all
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "ClusterRole"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_wildcard_verbs" in vio_ids
        assert rbac[0]["managed"] is True

    def test_wildcard_resources(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "role-res.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wide-role
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get", "list"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "Role"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_wildcard_resources" in vio_ids
        # wildcard resources also implies secrets access
        assert "rbac_secrets_access" in vio_ids

    def test_clean_role(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "role-clean.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "Role"]
        assert len(rbac) == 1
        assert rbac[0]["status"] == "clean"


class TestRBACDangerousCombos:
    def test_pods_exec(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "exec.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: exec-role
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_pods_exec" in vio_ids

    def test_secrets_get(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "secrets.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_secrets_access" in vio_ids

    def test_escalate_verb(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "esc.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalator
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["escalate"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_escalate_bind" in vio_ids

    def test_create_pods(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "create-pods.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-creator
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_create_pods" in vio_ids

    def test_nodes_proxy(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "nodeproxy.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-proxy
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_nodes_proxy" in vio_ids

    def test_sa_token_create(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "satoken.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sa-impersonator
rules:
- apiGroups: [""]
  resources: ["serviceaccounts/token"]
  verbs: ["create"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_sa_token_create" in vio_ids


class TestRBACBindings:
    def test_binding_default_sa(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "binding.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default-admin
subjects:
- kind: ServiceAccount
  name: default
  namespace: production
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "clusterrole_binds_default_sa" in vio_ids

    def test_binding_named_sa_clean(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "binding-ok.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-binding
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        bindings = [r for r in result["results"] if r["kind"] == "RoleBinding"]
        assert len(bindings) == 1
        assert bindings[0]["status"] == "clean"


class TestRBACImpersonate:
    def test_rbac_impersonate(self, tmp_path):
        """Role with impersonate verb should trigger alert."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "impersonate.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups"]
  verbs: ["impersonate"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "ClusterRole"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_impersonate" in vio_ids

    def test_rbac_no_impersonate_clean(self, tmp_path):
        """Role without impersonate verb should not trigger the rule."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-impersonate.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "Role"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_impersonate" not in vio_ids


class TestRBACConfigmapAccess:
    def test_rbac_configmap_access(self, tmp_path):
        """Role with get on configmaps should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "configmap-read.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: configmap-reader
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "ClusterRole"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_configmap_access" in vio_ids

    def test_rbac_configmap_create_not_flagged(self, tmp_path):
        """Role with only create on configmaps should not trigger the rule."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "configmap-create.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-creator
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["create"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "Role"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_configmap_access" not in vio_ids


class TestRBACCreateClusterRoleBindings:
    def test_rbac_create_clusterrolebindings(self, tmp_path):
        """Role with create on clusterrolebindings should trigger alert."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "crb-create.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: escalator
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["create"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "ClusterRole"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_create_clusterrolebindings" in vio_ids

    def test_rbac_get_clusterrolebindings_not_flagged(self, tmp_path):
        """Role with only get on clusterrolebindings should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "crb-get.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: crb-viewer
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["get", "list"]
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        rbac = [r for r in result["results"] if r["kind"] == "ClusterRole"]
        assert len(rbac) == 1
        vio_ids = [v["id"] for v in rbac[0]["violations"]]
        assert "rbac_create_clusterrolebindings" not in vio_ids


# ================================================================== #
# Phase 2: Infrastructure resources
# ================================================================== #


class TestNamespacePSA:
    def test_namespace_no_psa_label(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ns.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: production
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "psa_enforce_missing" in vio_ids

    def test_namespace_psa_privileged(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ns-priv.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: dangerous-ns
  labels:
    pod-security.kubernetes.io/enforce: privileged
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "psa_enforce_privileged" in vio_ids

    def test_namespace_psa_restricted_clean(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ns-ok.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: secure-ns
  labels:
    pod-security.kubernetes.io/enforce: restricted
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        ns = [r for r in result["results"] if r["kind"] == "Namespace"]
        # 2 results: the Namespace PSA check (clean) + isolation check
        assert len(ns) == 2
        psa_result = [r for r in ns if r["status"] == "clean"]
        assert len(psa_result) == 1
        assert psa_result[0]["managed"] is True


class TestSecretPlaintext:
    def test_secret_with_data(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "secret.yaml",
            """\
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
data:
  password: cGFzc3dvcmQxMjM=
  username: YWRtaW4=
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "secret_plaintext_in_manifest" in vio_ids

    def test_secret_without_data_clean(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "secret-empty.yaml",
            """\
apiVersion: v1
kind: Secret
metadata:
  name: empty-secret
type: Opaque
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        secrets = [r for r in result["results"] if r["kind"] == "Secret"]
        assert len(secrets) == 1
        assert secrets[0]["status"] == "clean"


class TestNetworkPolicy:
    def test_netpol_allow_all_ingress(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "netpol-wide.yaml",
            """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
spec:
  podSelector: {}
  ingress:
  - {}
  policyTypes:
  - Ingress
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "netpol_ingress_allow_all" in vio_ids

    def test_netpol_allow_all_egress(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "netpol-egress.yaml",
            """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
spec:
  podSelector: {}
  egress:
  - {}
  policyTypes:
  - Egress
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "netpol_egress_allow_all" in vio_ids

    def test_netpol_restrictive_clean(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "netpol-ok.yaml",
            """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        netpols = [r for r in result["results"] if r["kind"] == "NetworkPolicy"]
        assert len(netpols) == 1
        assert netpols[0]["status"] == "clean"


class TestMixedManifest:
    """Test multi-doc YAML with Pod + RBAC + Infra resources."""

    def test_mixed_resource_types(self, tmp_path):
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "mixed.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: app-ns
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
---
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  automountServiceAccountToken: false
  securityContext:
    fsGroup: 1000
    seLinuxOptions:
      type: container_t
  containers:
  - name: web
    image: nginx:1.25
    imagePullPolicy: Always
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      limits:
        cpu: "100m"
        memory: "64Mi"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        # 4 results: Namespace PSA, Role, Pod container, Namespace isolation
        assert result["summary"]["kubernetes_scanned"] == 4
        kinds = {r["kind"] for r in result["results"]}
        assert "Namespace" in kinds
        assert "Role" in kinds
        assert "Pod" in kinds
        # Per-resource scans should be clean; namespace isolation
        # violations are expected (no ResourceQuota/NetworkPolicy)
        isolation_vios = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "namespace_quota_missing" in isolation_vios
        assert "namespace_default_deny_missing" in isolation_vios
        # Non-isolation results should all be clean
        for r in result["results"]:
            if any(
                v["id"] in ("namespace_quota_missing", "namespace_default_deny_missing")
                for v in r["violations"]
            ):
                continue
            assert r["status"] == "clean", (
                f"{r['kind']}/{r['resource']} has violations: "
                f"{[v['id'] for v in r['violations']]}"
            )


# ================================================================== #
# Phase 3: Kubelet / K3s / RKE2 node configuration
# ================================================================== #


class TestKubeletConfig:
    def test_insecure_kubelet_config(self, tmp_path):
        root = _make_rootfs(tmp_path)
        # kubeadm detection hint
        (root / "etc" / "kubernetes" / "manifests").mkdir(parents=True)
        _write_yaml(
            root / "var" / "lib" / "kubelet" / "config.yaml",
            """\
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: true
authorization:
  mode: AlwaysAllow
readOnlyPort: 10255
protectKernelDefaults: false
streamingConnectionIdleTimeout: "0"
eventRecordQPS: 0
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_anonymous_auth_enabled" in vio_ids
        assert "kubelet_authorization_always_allow" in vio_ids
        assert "kubelet_readonly_port_enabled" in vio_ids
        assert "kubelet_protect_kernel_defaults_disabled" in vio_ids
        assert "kubelet_streaming_connection_timeout_disabled" in vio_ids
        assert "kubelet_event_record_qps_disabled" in vio_ids
        assert "kubelet_tls_cert_missing" in vio_ids

    def test_secure_kubelet_config(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "kubernetes" / "manifests").mkdir(parents=True)
        _write_yaml(
            root / "var" / "lib" / "kubelet" / "config.yaml",
            """\
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
rotateCertificates: true
serverTLSBootstrap: true
eventRecordQPS: 5
streamingConnectionIdleTimeout: "5m"
""",
        )
        ctx = _make_context()
        ctx.set_service_meta(
            "kubernetes",
            "",
            {
                "unit": "kubelet.service",
                "user": "root",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE CAP_SYS_PTRACE",
            },
        )
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        assert node[0]["status"] == "clean"

    def test_kubelet_tls_cert_configured(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "kubernetes" / "manifests").mkdir(parents=True)
        _write_yaml(
            root / "var" / "lib" / "kubelet" / "config.yaml",
            """\
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_tls_cert_missing" not in vio_ids


class TestK3sConfig:
    def test_insecure_k3s_config(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=true"
  - "read-only-port=10255"
  - "authorization-mode=AlwaysAllow"
  - "streaming-connection-idle-timeout=0"
  - "event-qps=0"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_anonymous_auth_enabled" in vio_ids
        assert "kubelet_readonly_port_enabled" in vio_ids
        assert "kubelet_authorization_always_allow" in vio_ids
        assert "kubelet_streaming_connection_timeout_disabled" in vio_ids
        assert "kubelet_event_record_qps_disabled" in vio_ids

    def test_secure_k3s_config(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
protect-kernel-defaults: true
kubelet-arg:
  - "anonymous-auth=false"
  - "read-only-port=0"
  - "authorization-mode=Webhook"
""",
        )
        ctx = _make_context()
        ctx.set_service_meta(
            "k3s",
            "server",
            {
                "unit": "k3s.service",
                "user": "root",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
            },
        )
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        assert node[0]["status"] == "clean"


class TestRKE2Config:
    def test_insecure_rke2_config(self, tmp_path):
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "rke2").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "rke2" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=true"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_anonymous_auth_enabled" in vio_ids

    def test_no_config_file_no_crash(self, tmp_path):
        root = _make_rootfs(tmp_path)
        # RKE2 hint but no config file
        (root / "etc" / "rancher" / "rke2").mkdir(parents=True)
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        # Should not crash, just no NodeConfig results
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 0


# ================================================================== #
# Phase 4: Systemd daemon service cross-validation
# ================================================================== #


class TestSystemdDaemonServiceValidation:
    """Tests for systemd service cross-validation on K8s daemon nodes."""

    def test_k3s_systemd_service_missing(self, tmp_path):
        """K3s daemon without systemd service triggers alert."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
protect-kernel-defaults: true
kubelet-arg:
  - "anonymous-auth=false"
  - "read-only-port=0"
  - "authorization-mode=Webhook"
""",
        )
        ctx = _make_context()
        # No service meta set -> systemd_service_found will be false
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_systemd_service_missing" in vio_ids
        assert node[0]["managed"] is False

    def test_rke2_systemd_service_missing(self, tmp_path):
        """RKE2 daemon without systemd service triggers alert."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "rke2").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "rke2" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_systemd_service_missing" in vio_ids

    def test_kubeadm_systemd_service_missing(self, tmp_path):
        """Kubeadm kubelet without systemd service triggers alert."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "kubernetes" / "manifests").mkdir(parents=True)
        _write_yaml(
            root / "var" / "lib" / "kubelet" / "config.yaml",
            """\
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
rotateCertificates: true
serverTLSBootstrap: true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_systemd_service_missing" in vio_ids

    def test_k3s_systemd_caps_unrestricted(self, tmp_path):
        """K3s daemon with systemd service but no CapabilityBoundingSet."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
protect-kernel-defaults: true
kubelet-arg:
  - "anonymous-auth=false"
  - "read-only-port=0"
  - "authorization-mode=Webhook"
""",
        )
        ctx = _make_context()
        ctx.set_service_meta(
            "k3s",
            "server",
            {
                "unit": "k3s.service",
                "user": "root",
            },
        )
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_systemd_service_missing" not in vio_ids
        assert "kubelet_systemd_caps_unrestricted" in vio_ids

    def test_k3s_systemd_caps_restricted(self, tmp_path):
        """K3s daemon with systemd service and CapabilityBoundingSet passes."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
protect-kernel-defaults: true
kubelet-arg:
  - "anonymous-auth=false"
  - "read-only-port=0"
  - "authorization-mode=Webhook"
""",
        )
        ctx = _make_context()
        ctx.set_service_meta(
            "k3s",
            "server",
            {
                "unit": "k3s.service",
                "user": "root",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE CAP_SYS_PTRACE",
            },
        )
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_systemd_service_missing" not in vio_ids
        assert "kubelet_systemd_caps_unrestricted" not in vio_ids
        assert node[0]["managed"] is True

    def test_rke2_agent_service_meta_found(self, tmp_path):
        """RKE2 agent service meta is found when server is absent."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "rke2").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "rke2" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        # Only agent meta, no server meta
        ctx.set_service_meta(
            "rke2",
            "agent",
            {
                "unit": "rke2-agent.service",
                "user": "root",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
            },
        )
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "kubelet_systemd_service_missing" not in vio_ids
        assert "kubelet_systemd_caps_unrestricted" not in vio_ids


# ================================================================== #
# Phase 5: Control plane component scanning
# ================================================================== #


class TestControlPlaneAPIServer:
    """Tests for kube-apiserver static pod manifest scanning."""

    def test_insecure_apiserver(self, tmp_path):
        """API server with insecure flags produces violations."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=true
    - --insecure-port=8080
    - --authorization-mode=AlwaysAllow
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        assert len(cp) >= 1
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        vio_ids = [v["id"] for v in apiserver[0]["violations"]]
        assert "apiserver_anonymous_auth" in vio_ids
        assert "apiserver_insecure_port" in vio_ids
        assert "apiserver_authz_not_rbac" in vio_ids
        assert "apiserver_encryption_missing" in vio_ids
        assert "apiserver_admission_missing" in vio_ids

    def test_secure_apiserver(self, tmp_path):
        """API server with secure flags produces no violations."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=false
    - --insecure-port=0
    - --authorization-mode=Node,RBAC
    - --encryption-provider-config=/etc/kubernetes/enc.yaml
    - --enable-admission-plugins=NodeRestriction,PodSecurity
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        assert apiserver[0]["status"] == "clean"
        assert apiserver[0]["violations"] == []
        assert apiserver[0]["managed"] is True


class TestControlPlaneEtcd:
    """Tests for etcd static pod manifest scanning."""

    def test_etcd_no_tls(self, tmp_path):
        """etcd without TLS produces violations."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "etcd.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: etcd
spec:
  containers:
  - name: etcd
    image: registry.k8s.io/etcd:3.5.10
    command:
    - etcd
    - --auto-tls=true
    - --listen-client-urls=http://0.0.0.0:2379
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        etcd = [r for r in cp if r["resource"] == "etcd"]
        assert len(etcd) == 1
        vio_ids = [v["id"] for v in etcd[0]["violations"]]
        assert "etcd_client_cert_missing" in vio_ids
        assert "etcd_client_key_missing" in vio_ids
        assert "etcd_peer_cert_missing" in vio_ids
        assert "etcd_peer_key_missing" in vio_ids
        assert "etcd_client_auto_tls" in vio_ids


class TestControlPlaneControllerManager:
    """Tests for kube-controller-manager static pod manifest scanning."""

    def test_cm_without_sa_key(self, tmp_path):
        """Controller manager without SA key produces violations."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-controller-manager.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
spec:
  containers:
  - name: kube-controller-manager
    image: registry.k8s.io/kube-controller-manager:v1.29.0
    command:
    - kube-controller-manager
    - --leader-elect=true
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        cm = [r for r in cp if r["resource"] == "kube-controller-manager"]
        assert len(cm) == 1
        vio_ids = [v["id"] for v in cm[0]["violations"]]
        assert "cm_sa_key_missing" in vio_ids
        assert "cm_root_ca_missing" in vio_ids
        assert "cm_sa_credentials_disabled" in vio_ids


class TestRBACBindsAnonymous:
    """Tests for ClusterRoleBinding to system:anonymous/unauthenticated."""

    def test_binding_to_anonymous_user(self, tmp_path):
        """Binding to system:anonymous triggers violation."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "anon-binding.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: anon-access
subjects:
- kind: User
  name: system:anonymous
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_binds_anonymous" in vio_ids

    def test_binding_to_unauthenticated_group(self, tmp_path):
        """Binding to system:unauthenticated group triggers violation."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "unauth-binding.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: unauth-access
subjects:
- kind: Group
  name: system:unauthenticated
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_binds_anonymous" in vio_ids

    def test_binding_to_named_user_no_anonymous_flag(self, tmp_path):
        """Binding to a regular user does not trigger anonymous flag."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "user-binding.yaml",
            """\
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: user-access
subjects:
- kind: User
  name: admin-user
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "rbac_binds_anonymous" not in vio_ids


class TestK3sControlPlaneArgs:
    """Tests for K3s config.yaml with kube-apiserver-arg."""

    def test_k3s_apiserver_args_insecure(self, tmp_path):
        """K3s config with insecure apiserver args produces violations."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kube-apiserver-arg:
  - "anonymous-auth=true"
  - "authorization-mode=AlwaysAllow"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        k3s_api = [r for r in cp if r["resource"] == "k3s-apiserver"]
        assert len(k3s_api) == 1
        vio_ids = [v["id"] for v in k3s_api[0]["violations"]]
        assert "apiserver_anonymous_auth" in vio_ids
        assert "apiserver_authz_not_rbac" in vio_ids


# ================================================================== #
# Phase 6: New detections -- sysctls, SELinux, fsGroup, webhooks,
#           PSP, PV, audit logging, K3s token/registries
# ================================================================== #


class TestUnsafeSysctls:
    """Tests for unsafe sysctl detection in pod security context."""

    def test_unsafe_kernel_sysctl(self, tmp_path):
        """kernel.* sysctls should trigger violation."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sysctl.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-pod
spec:
  securityContext:
    sysctls:
    - name: kernel.shm_rmid_forced
      value: "1"
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "unsafe_sysctls" in vio_ids

    def test_unsafe_vm_sysctl(self, tmp_path):
        """vm.* sysctls should trigger violation."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sysctl-vm.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-vm-pod
spec:
  securityContext:
    sysctls:
    - name: vm.max_map_count
      value: "262144"
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "unsafe_sysctls" in vio_ids

    def test_unsafe_ip_forward_sysctl(self, tmp_path):
        """net.ipv4.ip_forward sysctl should trigger violation."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sysctl-fwd.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-fwd-pod
spec:
  securityContext:
    sysctls:
    - name: net.ipv4.ip_forward
      value: "1"
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "unsafe_sysctls" in vio_ids

    def test_safe_sysctl_not_flagged(self, tmp_path):
        """Safe sysctls like net.ipv4.ping_group_range should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sysctl-safe.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-safe-pod
spec:
  securityContext:
    sysctls:
    - name: net.ipv4.ping_group_range
      value: "0 65535"
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "unsafe_sysctls" not in vio_ids

    def test_no_sysctls_not_flagged(self, tmp_path):
        """Pod without sysctls should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-sysctl.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: no-sysctl-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "unsafe_sysctls" not in vio_ids


class TestSELinuxNotSet:
    """Tests for SELinux options detection."""

    def test_selinux_not_set(self, tmp_path):
        """Pod without SELinux options should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-selinux.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: no-selinux-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "selinux_not_set" in vio_ids

    def test_selinux_on_container(self, tmp_path):
        """Container-level SELinux options should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "selinux-container.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: selinux-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      seLinuxOptions:
        type: container_t
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "selinux_not_set" not in vio_ids

    def test_selinux_on_pod(self, tmp_path):
        """Pod-level SELinux options should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "selinux-pod-level.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: selinux-pod-level
spec:
  securityContext:
    seLinuxOptions:
      type: container_t
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "selinux_not_set" not in vio_ids


class TestFsGroupMissing:
    """Tests for fsGroup detection."""

    def test_fsgroup_missing(self, tmp_path):
        """Pod without fsGroup should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-fsgroup.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: no-fsgroup-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "fsgroup_missing" in vio_ids

    def test_fsgroup_set(self, tmp_path):
        """Pod with fsGroup should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "fsgroup.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: fsgroup-pod
spec:
  securityContext:
    fsGroup: 1000
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "fsgroup_missing" not in vio_ids


class TestWebhookFailurePolicy:
    """Tests for webhook failurePolicy: Ignore detection."""

    def test_webhook_failure_policy_ignore(self, tmp_path):
        """ValidatingWebhookConfiguration with Ignore should trigger alert."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "webhook.yaml",
            """\
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: unsafe-webhook
webhooks:
- name: validate.example.com
  failurePolicy: Ignore
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    operations: ["CREATE"]
  clientConfig:
    service:
      name: webhook-svc
      namespace: default
  admissionReviewVersions: ["v1"]
  sideEffects: None
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        webhooks = [
            r
            for r in result["results"]
            if r["kind"] == "ValidatingWebhookConfiguration"
        ]
        assert len(webhooks) == 1
        vio_ids = [v["id"] for v in webhooks[0]["violations"]]
        assert "webhook_failure_policy_ignore" in vio_ids

    def test_mutating_webhook_failure_ignore(self, tmp_path):
        """MutatingWebhookConfiguration with Ignore should trigger alert."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "mut-webhook.yaml",
            """\
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: unsafe-mutating
webhooks:
- name: mutate.example.com
  failurePolicy: Ignore
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    operations: ["CREATE"]
  clientConfig:
    service:
      name: webhook-svc
      namespace: default
  admissionReviewVersions: ["v1"]
  sideEffects: None
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        webhooks = [
            r for r in result["results"] if r["kind"] == "MutatingWebhookConfiguration"
        ]
        assert len(webhooks) == 1
        vio_ids = [v["id"] for v in webhooks[0]["violations"]]
        assert "webhook_failure_policy_ignore" in vio_ids

    def test_webhook_failure_policy_fail_clean(self, tmp_path):
        """Webhook with failurePolicy: Fail should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "webhook-ok.yaml",
            """\
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: safe-webhook
webhooks:
- name: validate.example.com
  failurePolicy: Fail
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    operations: ["CREATE"]
  clientConfig:
    service:
      name: webhook-svc
      namespace: default
  admissionReviewVersions: ["v1"]
  sideEffects: None
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        webhooks = [
            r
            for r in result["results"]
            if r["kind"] == "ValidatingWebhookConfiguration"
        ]
        assert len(webhooks) == 1
        assert webhooks[0]["status"] == "clean"


class TestPodSecurityPolicy:
    """Tests for PodSecurityPolicy detection."""

    def test_psp_exists(self, tmp_path):
        """PodSecurityPolicy resource should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "psp.yaml",
            """\
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  runAsUser:
    rule: MustRunAsNonRoot
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        psp = [r for r in result["results"] if r["kind"] == "PodSecurityPolicy"]
        assert len(psp) == 1
        vio_ids = [v["id"] for v in psp[0]["violations"]]
        assert "psp_exists" in vio_ids


class TestPersistentVolumeHostPath:
    """Tests for PersistentVolume hostPath detection."""

    def test_pv_with_hostpath(self, tmp_path):
        """PersistentVolume with hostPath should trigger alert."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "pv-hostpath.yaml",
            """\
apiVersion: v1
kind: PersistentVolume
metadata:
  name: local-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
  - ReadWriteOnce
  hostPath:
    path: /data/volumes/pv1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        pv = [r for r in result["results"] if r["kind"] == "PersistentVolume"]
        assert len(pv) == 1
        vio_ids = [v["id"] for v in pv[0]["violations"]]
        assert "pv_uses_hostpath" in vio_ids

    def test_pv_without_hostpath_clean(self, tmp_path):
        """PersistentVolume without hostPath should be clean."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "pv-nfs.yaml",
            """\
apiVersion: v1
kind: PersistentVolume
metadata:
  name: nfs-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
  - ReadWriteMany
  nfs:
    server: nfs-server.example.com
    path: /exports/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        pv = [r for r in result["results"] if r["kind"] == "PersistentVolume"]
        assert len(pv) == 1
        assert pv[0]["status"] == "clean"


class TestAuditLogging:
    """Tests for API server audit logging detection."""

    def test_apiserver_audit_log_missing(self, tmp_path):
        """API server without audit-log-path should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=false
    - --insecure-port=0
    - --authorization-mode=Node,RBAC
    - --encryption-provider-config=/etc/kubernetes/enc.yaml
    - --enable-admission-plugins=NodeRestriction,PodSecurity
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        vio_ids = [v["id"] for v in apiserver[0]["violations"]]
        assert "apiserver_audit_log_missing" in vio_ids
        assert "apiserver_audit_policy_missing" in vio_ids

    def test_apiserver_audit_configured_clean(self, tmp_path):
        """API server with both audit flags should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=false
    - --insecure-port=0
    - --authorization-mode=Node,RBAC
    - --encryption-provider-config=/etc/kubernetes/enc.yaml
    - --enable-admission-plugins=NodeRestriction,PodSecurity
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        vio_ids = [v["id"] for v in apiserver[0]["violations"]]
        assert "apiserver_audit_log_missing" not in vio_ids
        assert "apiserver_audit_policy_missing" not in vio_ids
        assert "apiserver_audit_retention_missing" not in vio_ids

    def test_k3s_apiserver_audit_missing(self, tmp_path):
        """K3s config without audit args should trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kube-apiserver-arg:
  - "anonymous-auth=false"
  - "authorization-mode=Node,RBAC"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        k3s_api = [r for r in cp if r["resource"] == "k3s-apiserver"]
        assert len(k3s_api) == 1
        vio_ids = [v["id"] for v in k3s_api[0]["violations"]]
        assert "apiserver_audit_log_missing" in vio_ids
        assert "apiserver_audit_policy_missing" in vio_ids


class TestK3sTokenPermissions:
    """Tests for K3s token file permission checks."""

    def test_k3s_token_world_readable(self, tmp_path):
        """K3s token with group/other read should trigger alert."""
        import os
        import stat

        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        token_path = root / "var" / "lib" / "rancher" / "k3s" / "server" / "token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("K10abc123::server:secret", encoding="utf-8")
        os.chmod(str(token_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_token_world_readable" in vio_ids

    def test_k3s_token_owner_only_clean(self, tmp_path):
        """K3s token with 0600 should not trigger."""
        import os
        import stat

        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        token_path = root / "var" / "lib" / "rancher" / "k3s" / "server" / "token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("K10abc123::server:secret", encoding="utf-8")
        os.chmod(str(token_path), stat.S_IRUSR | stat.S_IWUSR)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_token_world_readable" not in vio_ids

    def test_k3s_token_missing_not_flagged(self, tmp_path):
        """Missing K3s token file should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_token_world_readable" not in vio_ids


class TestK3sRegistriesSecrets:
    """Tests for K3s registries.yaml secrets detection."""

    def test_registries_with_password(self, tmp_path):
        """registries.yaml with password field should trigger alert."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        reg_path = root / "etc" / "rancher" / "k3s" / "registries.yaml"
        reg_path.write_text(
            """\
mirrors:
  docker.io:
    endpoint:
    - "https://registry.example.com"
configs:
  "registry.example.com":
    auth:
      username: admin
      password: s3cret
""",
            encoding="utf-8",
        )
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_registry_has_secrets" in vio_ids

    def test_registries_with_token(self, tmp_path):
        """registries.yaml with token field should trigger alert."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        reg_path = root / "etc" / "rancher" / "k3s" / "registries.yaml"
        reg_path.write_text(
            """\
configs:
  "registry.example.com":
    token: eyJhbGciOiJIUzI1NiJ9
""",
            encoding="utf-8",
        )
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_registry_has_secrets" in vio_ids

    def test_registries_without_secrets_clean(self, tmp_path):
        """registries.yaml without credentials should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        reg_path = root / "etc" / "rancher" / "k3s" / "registries.yaml"
        reg_path.write_text(
            """\
mirrors:
  docker.io:
    endpoint:
    - "https://registry.example.com"
""",
            encoding="utf-8",
        )
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_registry_has_secrets" not in vio_ids

    def test_registries_missing_not_flagged(self, tmp_path):
        """Missing registries.yaml should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_registry_has_secrets" not in vio_ids


# ================================================================== #
# Phase 7: Exec probes, insecure volumes, workload-specific risks,
#           K3s kubeconfig/datastore/token, audit retention
# ================================================================== #


class TestExecProbe:
    """Tests for exec probe detection."""

    def test_exec_liveness_probe(self, tmp_path):
        """Container with exec liveness probe should trigger info."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "exec-probe.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: exec-probe-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    livenessProbe:
      exec:
        command:
        - cat
        - /tmp/healthy
      initialDelaySeconds: 5
      periodSeconds: 10
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "exec_probe_used" in vio_ids

    def test_exec_readiness_probe(self, tmp_path):
        """Container with exec readiness probe should trigger info."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "exec-ready.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: exec-ready-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    readinessProbe:
      exec:
        command:
        - test
        - -f
        - /tmp/ready
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "exec_probe_used" in vio_ids

    def test_exec_startup_probe(self, tmp_path):
        """Container with exec startup probe should trigger info."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "exec-startup.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: exec-startup-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    startupProbe:
      exec:
        command:
        - cat
        - /tmp/started
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "exec_probe_used" in vio_ids

    def test_http_probe_not_flagged(self, tmp_path):
        """Container with httpGet probe should not trigger exec_probe_used."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "http-probe.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: http-probe-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "exec_probe_used" not in vio_ids

    def test_no_probe_not_flagged(self, tmp_path):
        """Container without probes should not trigger exec_probe_used."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "no-probe.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: no-probe-pod
spec:
  containers:
  - name: app
    image: myapp:v1
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "exec_probe_used" not in vio_ids


class TestInsecureVolumeType:
    """Tests for insecure volume type detection."""

    def test_nfs_volume(self, tmp_path):
        """Pod with NFS volume should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "nfs-vol.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: nfs-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    nfs:
      server: nfs-server.example.com
      path: /exports/data
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "insecure_volume_type" in vio_ids

    def test_iscsi_volume(self, tmp_path):
        """Pod with iSCSI volume should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "iscsi-vol.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: iscsi-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    iscsi:
      targetPortal: 10.0.0.1:3260
      iqn: iqn.2001-04.com.example:storage
      lun: 0
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "insecure_volume_type" in vio_ids

    def test_flexvolume(self, tmp_path):
        """Pod with flexVolume should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "flex-vol.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: flex-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    flexVolume:
      driver: example.com/driver
      options:
        key: value
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "insecure_volume_type" in vio_ids

    def test_emptydir_not_flagged(self, tmp_path):
        """Pod with emptyDir volume should not trigger insecure_volume_type."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "emptydir-vol.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: emptydir-pod
spec:
  containers:
  - name: app
    image: myapp:v1
    volumeMounts:
    - name: cache
      mountPath: /cache
  volumes:
  - name: cache
    emptyDir: {}
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "insecure_volume_type" not in vio_ids


class TestDaemonSetDetection:
    """Tests for DaemonSet-specific risk detection."""

    def test_daemonset_detected(self, tmp_path):
        """DaemonSet should trigger daemonset_detected info."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ds-detect.yaml",
            """\
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-exporter
spec:
  selector:
    matchLabels:
      app: node-exporter
  template:
    metadata:
      labels:
        app: node-exporter
    spec:
      containers:
      - name: exporter
        image: prom/node-exporter:v1.7.0
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "daemonset_detected" in vio_ids

    def test_deployment_not_flagged_as_daemonset(self, tmp_path):
        """Deployment should not trigger daemonset_detected."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "deploy.yaml",
            """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "daemonset_detected" not in vio_ids


class TestCronJobNoHistory:
    """Tests for CronJob history limit detection."""

    def test_cronjob_success_limit_zero(self, tmp_path):
        """CronJob with successfulJobsHistoryLimit=0 should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "cron-nohist.yaml",
            """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup-nohist
spec:
  schedule: "0 * * * *"
  successfulJobsHistoryLimit: 0
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleaner
            image: busybox:1.36
            command: ["sh", "-c", "echo cleanup"]
          restartPolicy: OnFailure
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "cronjob_no_history" in vio_ids

    def test_cronjob_failed_limit_zero(self, tmp_path):
        """CronJob with failedJobsHistoryLimit=0 should trigger warning."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "cron-nofail.yaml",
            """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup-nofail
spec:
  schedule: "0 * * * *"
  failedJobsHistoryLimit: 0
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleaner
            image: busybox:1.36
            command: ["sh", "-c", "echo cleanup"]
          restartPolicy: OnFailure
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "cronjob_no_history" in vio_ids

    def test_cronjob_default_limits_not_flagged(self, tmp_path):
        """CronJob without explicit limit (default) should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "cron-default.yaml",
            """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup-default
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleaner
            image: busybox:1.36
            command: ["sh", "-c", "echo cleanup"]
          restartPolicy: OnFailure
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "cronjob_no_history" not in vio_ids

    def test_deployment_not_flagged_as_cronjob(self, tmp_path):
        """Deployment should not trigger cronjob_no_history."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "deploy-nocron.yaml",
            """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.25
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        vio_ids = [v["id"] for r in result["results"] for v in r["violations"]]
        assert "cronjob_no_history" not in vio_ids


class TestK3sKubeconfigPermissions:
    """Tests for K3s kubeconfig permission checks."""

    def test_k3s_kubeconfig_world_readable(self, tmp_path):
        """K3s kubeconfig with group/other read should trigger alert."""
        import os
        import stat

        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        kc_path = root / "etc" / "rancher" / "k3s" / "k3s.yaml"
        kc_path.write_text("apiVersion: v1\nclusters: []\n", encoding="utf-8")
        os.chmod(str(kc_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_kubeconfig_world_readable" in vio_ids

    def test_k3s_kubeconfig_owner_only_clean(self, tmp_path):
        """K3s kubeconfig with 0600 should not trigger."""
        import os
        import stat

        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        kc_path = root / "etc" / "rancher" / "k3s" / "k3s.yaml"
        kc_path.write_text("apiVersion: v1\nclusters: []\n", encoding="utf-8")
        os.chmod(str(kc_path), stat.S_IRUSR | stat.S_IWUSR)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_kubeconfig_world_readable" not in vio_ids

    def test_k3s_kubeconfig_missing_not_flagged(self, tmp_path):
        """Missing kubeconfig should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_kubeconfig_world_readable" not in vio_ids


class TestK3sDatastoreNoTLS:
    """Tests for K3s datastore endpoint TLS check."""

    def test_datastore_http_triggers(self, tmp_path):
        """datastore-endpoint with http:// should trigger alert."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
datastore-endpoint: "http://etcd.example.com:2379"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_datastore_no_tls" in vio_ids

    def test_datastore_https_clean(self, tmp_path):
        """datastore-endpoint with https:// should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
datastore-endpoint: "https://etcd.example.com:2379"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_datastore_no_tls" not in vio_ids

    def test_no_datastore_not_flagged(self, tmp_path):
        """No datastore-endpoint should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_datastore_no_tls" not in vio_ids


class TestK3sStaticToken:
    """Tests for K3s static bootstrap token detection."""

    def test_static_token_triggers(self, tmp_path):
        """config.yaml with token but no token-file should trigger warning."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
token: "mysecrettoken123"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_static_token" in vio_ids

    def test_token_file_clean(self, tmp_path):
        """config.yaml with both token and token-file should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
token: "mysecrettoken123"
token-file: "/etc/rancher/k3s/token-file"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_static_token" not in vio_ids

    def test_no_token_not_flagged(self, tmp_path):
        """config.yaml without token key should not trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        node = [r for r in result["results"] if r["kind"] == "NodeConfig"]
        assert len(node) == 1
        vio_ids = [v["id"] for v in node[0]["violations"]]
        assert "k3s_static_token" not in vio_ids


class TestApiserverAuditRetention:
    """Tests for API server audit log retention detection."""

    def test_audit_enabled_no_retention(self, tmp_path):
        """API server with audit-log-path but no retention flags."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=false
    - --insecure-port=0
    - --authorization-mode=Node,RBAC
    - --encryption-provider-config=/etc/kubernetes/enc.yaml
    - --enable-admission-plugins=NodeRestriction,PodSecurity
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        vio_ids = [v["id"] for v in apiserver[0]["violations"]]
        assert "apiserver_audit_retention_missing" in vio_ids

    def test_audit_enabled_with_retention_clean(self, tmp_path):
        """API server with audit logging and retention should not trigger."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=false
    - --insecure-port=0
    - --authorization-mode=Node,RBAC
    - --encryption-provider-config=/etc/kubernetes/enc.yaml
    - --enable-admission-plugins=NodeRestriction,PodSecurity
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
    - --audit-log-maxage=30
    - --audit-log-maxbackup=10
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        vio_ids = [v["id"] for v in apiserver[0]["violations"]]
        assert "apiserver_audit_retention_missing" not in vio_ids

    def test_audit_disabled_no_retention_not_flagged(self, tmp_path):
        """API server without audit-log-path should not trigger retention."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "kube-apiserver.yaml",
            """\
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - name: kube-apiserver
    image: registry.k8s.io/kube-apiserver:v1.29.0
    command:
    - kube-apiserver
    - --anonymous-auth=false
    - --insecure-port=0
    - --authorization-mode=Node,RBAC
    - --encryption-provider-config=/etc/kubernetes/enc.yaml
    - --enable-admission-plugins=NodeRestriction,PodSecurity
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        apiserver = [r for r in cp if r["resource"] == "kube-apiserver"]
        assert len(apiserver) == 1
        vio_ids = [v["id"] for v in apiserver[0]["violations"]]
        assert "apiserver_audit_retention_missing" not in vio_ids

    def test_k3s_audit_retention_missing(self, tmp_path):
        """K3s config with audit-log-path but no retention should trigger."""
        root = _make_rootfs(tmp_path)
        (root / "etc" / "rancher" / "k3s").mkdir(parents=True)
        _write_yaml(
            root / "etc" / "rancher" / "k3s" / "config.yaml",
            """\
kube-apiserver-arg:
  - "anonymous-auth=false"
  - "authorization-mode=Node,RBAC"
  - "audit-log-path=/var/log/kubernetes/audit.log"
  - "audit-policy-file=/etc/kubernetes/audit-policy.yaml"
kubelet-arg:
  - "anonymous-auth=false"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        cp = [r for r in result["results"] if r["kind"] == "ControlPlane"]
        k3s_api = [r for r in cp if r["resource"] == "k3s-apiserver"]
        assert len(k3s_api) == 1
        vio_ids = [v["id"] for v in k3s_api[0]["violations"]]
        assert "apiserver_audit_retention_missing" in vio_ids


# ================================================================== #
# Cross-manifest namespace analysis
# ================================================================== #


class TestNamespaceIsolation:
    def test_namespace_missing_quota_and_netpol(self, tmp_path):
        """Namespace without ResourceQuota or default-deny should be flagged."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "ns.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: app-ns
  labels:
    pod-security.kubernetes.io/enforce: restricted
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        iso = [
            r
            for r in result["results"]
            if r["kind"] == "Namespace" and r["status"] == "violated"
        ]
        assert len(iso) == 1
        vio_ids = [v["id"] for v in iso[0]["violations"]]
        assert "namespace_quota_missing" in vio_ids
        assert "namespace_default_deny_missing" in vio_ids

    def test_namespace_with_quota_and_netpol_clean(self, tmp_path):
        """Namespace with ResourceQuota + default-deny should pass."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "full.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: secure-app
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: secure-app
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: secure-app
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        # Namespace PSA check should be clean, and no isolation violation
        ns_results = [r for r in result["results"] if r["kind"] == "Namespace"]
        # Only 1 Namespace result (PSA clean), no isolation entry
        assert len(ns_results) == 1
        assert ns_results[0]["status"] == "clean"

    def test_system_namespaces_skipped(self, tmp_path):
        """kube-system, kube-public should not trigger isolation check."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "sys.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        iso = [
            r
            for r in result["results"]
            if r["status"] == "violated"
            and any(v["id"] == "namespace_quota_missing" for v in r["violations"])
        ]
        # kube-system should NOT get isolation violations
        assert len(iso) == 0

    def test_quota_present_netpol_missing(self, tmp_path):
        """Namespace with ResourceQuota but no NetworkPolicy."""
        root = _make_rootfs(tmp_path)
        _write_yaml(
            root / "etc" / "kubernetes" / "manifests" / "partial.yaml",
            """\
apiVersion: v1
kind: Namespace
metadata:
  name: partial-ns
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: quota
  namespace: partial-ns
spec:
  hard:
    pods: "10"
""",
        )
        ctx = _make_context()
        result = kubernetes.scan(str(root), context=ctx)
        iso = [
            r
            for r in result["results"]
            if r["kind"] == "Namespace" and r["status"] == "violated"
        ]
        assert len(iso) == 1
        vio_ids = [v["id"] for v in iso[0]["violations"]]
        assert "namespace_quota_missing" not in vio_ids
        assert "namespace_default_deny_missing" in vio_ids
