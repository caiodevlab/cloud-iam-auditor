"""Testes das regras de detecção IAM."""
import pytest
from iam_auditor.rules import (
    analyze_policy,
    analyze_trust_policy,
    Severity,
)


class TestPolicyRules:
    """Testes para analyze_policy()."""

    def test_wildcard_action_detected(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::bucket",
            }]
        }
        result = analyze_policy(policy, "test-role", "role")
        assert result.clean is False
        assert any(i.rule_id == "WILDCARD_ACTION" for i in result.issues)

    def test_clean_policy_no_issues(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }]
        }
        result = analyze_policy(policy, "test-role", "role")
        assert result.clean is True
        assert len(result.issues) == 0

    def test_fullaccess_detected(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }]
        }
        result = analyze_policy(policy, "admin-user", "user")
        assert any(i.rule_id == "EXCESSIVE_ACCESS" for i in result.issues)

    def test_unrestricted_passrole(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["iam:PassRole", "lambda:InvokeFunction"],
                "Resource": "*",
            }]
        }
        result = analyze_policy(policy, "lambda-invoker", "role")
        assert any(i.rule_id == "UNRESTRICTED_PASSROLE" for i in result.issues)


class TestTrustPolicyRules:
    """Testes para analyze_trust_policy()."""

    def test_public_trust_detected(self):
        trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
            }]
        }
        result = analyze_trust_policy(trust, "my-role")
        assert result.clean is False
        assert any(i.rule_id == "PUBLIC_TRUST" for i in result.issues)

    def test_restricted_trust_clean(self):
        trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789:root"},
                "Action": "sts:AssumeRole",
            }]
        }
        result = analyze_trust_policy(trust, "internal-role")
        assert result.clean is True
