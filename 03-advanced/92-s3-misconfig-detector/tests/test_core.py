"""Tests for project_92 core — S3 Misconfiguration Detector."""

from __future__ import annotations

import json
from pathlib import Path

from project_92.core import (
    analyze_bucket_policy,
    analyze_policy_file,
    check_public_acl_change,
    check_public_list,
    check_public_read,
    check_public_write,
    check_wildcard_action_authenticated,
)


def _stmt(effect: str, principal: Any, actions: Any, resources: Any = "*", sid: str = "test") -> dict:
    return {"Effect": effect, "Sid": sid, "Principal": principal,
            "Action": actions, "Resource": resources}


from typing import Any

# ── check_public_read ─────────────────────────────────────────────────────────

class TestPublicRead:
    def test_star_principal_get_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:GetObject")
        assert check_public_read(s, "bucket") is not None

    def test_star_principal_with_condition_no_trigger(self) -> None:
        s = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
             "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-123"}}}
        assert check_public_read(s, "bucket") is None

    def test_deny_effect_no_trigger(self) -> None:
        s = _stmt("Deny", "*", "s3:GetObject")
        assert check_public_read(s, "bucket") is None

    def test_specific_principal_no_trigger(self) -> None:
        s = _stmt("Allow", {"AWS": "arn:aws:iam::123:role/my-role"}, "s3:GetObject")
        assert check_public_read(s, "bucket") is None

    def test_rule_id_s3_001(self) -> None:
        s = _stmt("Allow", "*", "s3:GetObject")
        finding = check_public_read(s, "bucket")
        assert finding is not None
        assert finding.rule_id == "S3-001"
        assert finding.severity == "CRITICAL"


# ── check_public_write ────────────────────────────────────────────────────────

class TestPublicWrite:
    def test_put_object_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:PutObject")
        assert check_public_write(s, "bucket") is not None

    def test_delete_object_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:DeleteObject")
        assert check_public_write(s, "bucket") is not None

    def test_s3_star_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:*")
        assert check_public_write(s, "bucket") is not None

    def test_list_only_no_trigger(self) -> None:
        s = _stmt("Allow", "*", "s3:ListBucket")
        assert check_public_write(s, "bucket") is None


# ── check_public_list ─────────────────────────────────────────────────────────

class TestPublicList:
    def test_list_bucket_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:ListBucket")
        assert check_public_list(s, "bucket") is not None

    def test_get_object_no_trigger(self) -> None:
        s = _stmt("Allow", "*", "s3:GetObject")
        assert check_public_list(s, "bucket") is None

    def test_severity_high(self) -> None:
        s = _stmt("Allow", "*", "s3:ListBucket")
        finding = check_public_list(s, "bucket")
        assert finding is not None
        assert finding.severity == "HIGH"


# ── check_public_acl_change ───────────────────────────────────────────────────

class TestPublicACLChange:
    def test_put_bucket_acl_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:PutBucketAcl")
        assert check_public_acl_change(s, "bucket") is not None

    def test_put_object_acl_triggers(self) -> None:
        s = _stmt("Allow", "*", "s3:PutObjectAcl")
        assert check_public_acl_change(s, "bucket") is not None


# ── check_wildcard_action_authenticated ───────────────────────────────────────

class TestWildcardActionAuthenticated:
    def test_s3_star_to_role(self) -> None:
        s = _stmt("Allow", {"AWS": "arn:aws:iam::123:role/app"}, "s3:*")
        assert check_wildcard_action_authenticated(s, "bucket") is not None

    def test_s3_star_with_condition_no_trigger(self) -> None:
        s = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/app"},
             "Action": "s3:*", "Resource": "*",
             "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-1"}}}
        assert check_wildcard_action_authenticated(s, "bucket") is None

    def test_public_principal_not_caught_by_this_rule(self) -> None:
        s = _stmt("Allow", "*", "s3:*")
        assert check_wildcard_action_authenticated(s, "bucket") is None


# ── analyze_bucket_policy ─────────────────────────────────────────────────────

class TestAnalyzeBucketPolicy:
    def test_public_bucket_multi_findings(self) -> None:
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject", "s3:ListBucket"],
                 "Resource": ["arn:aws:s3:::public-bucket/*", "arn:aws:s3:::public-bucket"]},
            ]
        }
        result = analyze_bucket_policy(policy, "public-bucket")
        assert len(result.findings) >= 2

    def test_clean_policy_no_findings(self) -> None:
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:role/app"},
                 "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*"},
            ]
        }
        result = analyze_bucket_policy(policy, "my-bucket")
        assert result.findings == []

    def test_deduplication(self) -> None:
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"},
            ]
        }
        result = analyze_bucket_policy(policy, "x")
        ids = [f.rule_id for f in result.findings]
        assert len(ids) == len(set(ids))

    def test_to_dict_structure(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:*",
                                  "Resource": "*"}]}
        result = analyze_bucket_policy(policy, "bucket")
        d = result.to_dict()
        assert "findings" in d
        assert "by_severity" in d
        assert "total_findings" in d


# ── analyze_policy_file ───────────────────────────────────────────────────────

class TestAnalyzePolicyFile:
    def test_load_and_analyze(self, tmp_path: Path) -> None:
        policy = {
            "Statement": [{"Effect": "Allow", "Principal": "*",
                           "Action": "s3:GetObject", "Resource": "*"}]
        }
        f = tmp_path / "my-bucket.json"
        f.write_text(json.dumps(policy))
        result = analyze_policy_file(f)
        assert result.bucket_name == "my-bucket"
        assert len(result.findings) > 0
