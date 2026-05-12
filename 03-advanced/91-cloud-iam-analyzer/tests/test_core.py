"""Tests for project_91 core — Cloud IAM Policy Analyzer."""

from __future__ import annotations

import json
from pathlib import Path

from project_91.core import (
    analyze_policy_dict,
    analyze_policy_file,
    analyze_statement,
)


def _stmt(actions: list[str] | str, resources: list[str] | str, sid: str = "test") -> dict:
    return {"Effect": "Allow", "Sid": sid, "Action": actions, "Resource": resources}


# ── analyze_statement ─────────────────────────────────────────────────────────

class TestFullAdmin:
    def test_star_action_star_resource_triggers_iam001(self) -> None:
        f = analyze_statement(_stmt("*", "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-001" in ids

    def test_deny_effect_no_findings(self) -> None:
        stmt = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        assert analyze_statement(stmt, "pol") == []

    def test_iam001_severity_critical(self) -> None:
        f = analyze_statement(_stmt("*", "*"), "pol")
        crit = [x for x in f if x.rule_id == "IAM-001"]
        assert crit[0].severity == "CRITICAL"


class TestPrivilegeEscalation:
    def test_iam_create_policy_version(self) -> None:
        f = analyze_statement(_stmt(["iam:CreatePolicyVersion"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-003" in ids

    def test_sts_assume_role(self) -> None:
        f = analyze_statement(_stmt(["sts:AssumeRole"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-003" in ids

    def test_safe_action_no_escalation(self) -> None:
        f = analyze_statement(_stmt(["s3:GetObject"], "arn:aws:s3:::my-bucket/*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-003" not in ids


class TestDataExfil:
    def test_s3_star_on_wildcard_resource(self) -> None:
        f = analyze_statement(_stmt(["s3:*"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-004" in ids

    def test_secret_manager_read(self) -> None:
        f = analyze_statement(_stmt(["secretsmanager:GetSecretValue"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-004" in ids

    def test_scoped_resource_no_trigger(self) -> None:
        f = analyze_statement(_stmt(["s3:GetObject"], "arn:aws:s3:::my-bucket/specific-key"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-004" not in ids


class TestInfraDestroy:
    def test_ec2_terminate(self) -> None:
        f = analyze_statement(_stmt(["ec2:TerminateInstances"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-005" in ids

    def test_s3_delete_bucket(self) -> None:
        f = analyze_statement(_stmt(["s3:DeleteBucket"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-005" in ids


class TestLoggingDisable:
    def test_cloudtrail_stop_logging(self) -> None:
        f = analyze_statement(_stmt(["cloudtrail:StopLogging"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-006" in ids

    def test_guardduty_delete_detector(self) -> None:
        f = analyze_statement(_stmt(["guardduty:DeleteDetector"], "*"), "pol")
        ids = {x.rule_id for x in f}
        assert "IAM-006" in ids


# ── analyze_policy_dict ───────────────────────────────────────────────────────

class TestAnalyzePolicyDict:
    def test_admin_policy(self) -> None:
        policy = {"Version": "2012-10-17", "Statement": [_stmt("*", "*")]}
        result = analyze_policy_dict(policy, "AdminPolicy")
        assert result.policy_name == "AdminPolicy"
        assert len(result.findings) > 0

    def test_clean_policy(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [_stmt(["s3:GetObject"], "arn:aws:s3:::my-bucket/key")],
        }
        result = analyze_policy_dict(policy, "ReadOnly")
        assert len(result.findings) == 0

    def test_multi_statement_policy(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                _stmt(["cloudtrail:StopLogging"], "*", "DisableLogging"),
                _stmt(["s3:GetObject"], "arn:aws:s3:::bucket/key", "ReadFile"),
            ],
        }
        result = analyze_policy_dict(policy, "Mixed")
        assert result.statement_count == 2
        ids = {f.rule_id for f in result.findings}
        assert "IAM-006" in ids

    def test_to_dict_structure(self) -> None:
        policy = {"Statement": [_stmt("*", "*")]}
        result = analyze_policy_dict(policy, "admin")
        d = result.to_dict()
        assert "findings" in d
        assert "by_severity" in d
        assert "total_findings" in d


# ── analyze_policy_file ───────────────────────────────────────────────────────

class TestAnalyzePolicyFile:
    def test_loads_json_file(self, tmp_path: Path) -> None:
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        f = tmp_path / "admin-policy.json"
        f.write_text(json.dumps(policy))
        result = analyze_policy_file(f)
        assert result.policy_name == "admin-policy"
        assert len(result.findings) > 0

    def test_clean_policy_file(self, tmp_path: Path) -> None:
        policy = {
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                           "Resource": "arn:aws:s3:::bucket/key"}]
        }
        f = tmp_path / "read-only.json"
        f.write_text(json.dumps(policy))
        result = analyze_policy_file(f)
        assert result.findings == []
