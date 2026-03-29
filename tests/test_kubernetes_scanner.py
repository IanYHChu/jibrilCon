"""Integration tests for the Kubernetes scanner module."""

from pathlib import Path

import pytest

from tests.conftest import _FAKE_SYSTEMD, _make_context, _write_binary

from jibrilcon.scanners import kubernetes

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
  containers:
  - name: app
    image: myapp:v1.0.0
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
  containers:
  - name: b
    image: app-b:v1
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
        assert len(ns) == 1
        assert ns[0]["status"] == "clean"


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
  containers:
  - name: web
    image: nginx:1.25
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
        # Should scan 3 resources: Namespace, Role, Pod container
        assert result["summary"]["kubernetes_scanned"] == 3
        kinds = {r["kind"] for r in result["results"]}
        assert "Namespace" in kinds
        assert "Role" in kinds
        assert "Pod" in kinds
        # All should be clean in this case
        for r in result["results"]:
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
