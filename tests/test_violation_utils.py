"""Tests for util/violation_utils.py."""

from jibrilcon.util.violation_utils import process_violations


# ------------------------------------------------------------------ #
# Tests
# ------------------------------------------------------------------ #


def test_normal_violation_processing():
    """Conditions and logic keys are removed; source and lines are set."""
    vios_raw = [
        {
            "id": "rule_1",
            "type": "alert",
            "description": "Test rule",
            "conditions": [
                {"field": "privileged", "op": "eq", "value": True},
            ],
            "logic": "and",
            "extra_field": "kept",
        },
    ]

    def resolver(v, used_fields):
        return [f"{f} = flagged" for f in used_fields]

    result = process_violations(
        vios_raw,
        cfg_path="/mnt/rootfs/var/lib/docker/containers/abc/config.v2.json",
        mount_path="/mnt/rootfs",
        line_resolver=resolver,
    )

    assert len(result) == 1
    v = result[0]
    # Internal keys removed
    assert "conditions" not in v
    assert "logic" not in v
    # Enriched keys present
    assert "source" in v
    assert "lines" in v
    # Extra fields preserved
    assert v["extra_field"] == "kept"


def test_source_is_relative_to_mount_path():
    """source field should be a slash-prefixed relative path."""
    vios_raw = [
        {
            "id": "r1",
            "type": "warning",
            "conditions": [{"field": "f", "op": "eq", "value": True}],
            "logic": "and",
        },
    ]

    result = process_violations(
        vios_raw,
        cfg_path="/mnt/rootfs/etc/docker/config.json",
        mount_path="/mnt/rootfs",
        line_resolver=lambda v, uf: [],
    )

    assert result[0]["source"] == "/etc/docker/config.json"


def test_line_resolver_callback_invoked():
    """The line_resolver receives the violation dict and the set of used fields."""
    captured = {}

    def resolver(v, used_fields):
        captured["violation_id"] = v["id"]
        captured["used_fields"] = used_fields
        return ["line_a", "line_b"]

    vios_raw = [
        {
            "id": "cap_check",
            "type": "alert",
            "conditions": [
                {"field": "cap_add", "op": "eq", "value": True},
                {"field": "privileged", "op": "eq", "value": False},
            ],
            "logic": "and",
        },
    ]

    result = process_violations(
        vios_raw,
        cfg_path="/rootfs/cfg",
        mount_path="/rootfs",
        line_resolver=resolver,
    )

    assert captured["violation_id"] == "cap_check"
    assert captured["used_fields"] == {"cap_add", "privileged"}
    assert result[0]["lines"] == ["line_a", "line_b"]


def test_empty_violations_list():
    """An empty violations list returns an empty result."""
    result = process_violations(
        [],
        cfg_path="/rootfs/cfg",
        mount_path="/rootfs",
        line_resolver=lambda v, uf: [],
    )
    assert result == []


def test_conditions_without_field_key():
    """Conditions missing the 'field' key should not contribute to used_fields."""
    vios_raw = [
        {
            "id": "r1",
            "type": "alert",
            "conditions": [
                {"op": "eq", "value": True},  # no "field" key
                {"field": "real_field", "op": "eq", "value": True},
            ],
            "logic": "and",
        },
    ]

    captured_fields = {}

    def resolver(v, used_fields):
        captured_fields["uf"] = used_fields
        return []

    process_violations(
        vios_raw,
        cfg_path="/rootfs/cfg",
        mount_path="/rootfs",
        line_resolver=resolver,
    )

    # Only "real_field" should be in the set; the empty/missing field is excluded
    assert captured_fields["uf"] == {"real_field"}


def test_multiple_violations_processed():
    """Multiple violations are each independently processed."""
    vios_raw = [
        {
            "id": "v1",
            "type": "alert",
            "conditions": [{"field": "a", "op": "eq", "value": True}],
            "logic": "and",
        },
        {
            "id": "v2",
            "type": "warning",
            "conditions": [{"field": "b", "op": "eq", "value": False}],
            "logic": "or",
        },
    ]

    result = process_violations(
        vios_raw,
        cfg_path="/rootfs/etc/config",
        mount_path="/rootfs",
        line_resolver=lambda v, uf: [f"line for {v['id']}"],
    )

    assert len(result) == 2
    assert result[0]["id"] == "v1"
    assert result[0]["lines"] == ["line for v1"]
    assert result[1]["id"] == "v2"
    assert result[1]["lines"] == ["line for v2"]
    # Both should have conditions/logic removed
    for v in result:
        assert "conditions" not in v
        assert "logic" not in v
