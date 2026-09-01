"""
Coleta dados IAM via boto3.
Usa paginators para handlear listas grandes.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import boto3
import botocore.exceptions

logger = logging.getLogger(__name__)


@dataclass
class IAMData:
    """Dados coletados de uma conta AWS."""
    account_id: str
    region: str
    users: list[dict] = field(default_factory=list)
    roles: list[dict] = field(default_factory=list)
    groups: list[dict] = field(default_factory=list)
    policies: list[dict] = field(default_factory=list)  # managed policies


def _paginate(client, method_name: str, **kwargs):
    """Wrapper em paginators do boto3."""
    paginator = client.get_paginator(method_name)
    for page in paginator.paginate(**kwargs).result_key_iters():
        yield page


def _safe_policy_parse(policy: str | dict | None) -> dict:
    """Tenta parsear uma policy de JSON. Retorna {} se falhar."""
    if not policy:
        return {}
    if isinstance(policy, dict):
        return policy
    try:
        return json.loads(policy)
    except (json.JSONDecodeError, TypeError):
        return {}


def collect_iam(
    profile: str | None = None,
    region: str = "us-east-1",
) -> IAMData:
    """
    Coleta todos os recursos IAM da conta: users, roles, groups, policies.
    Lança exception se não conseguir (falha de credenciais, etc.).
    """
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")
    sts = session.client("sts")

    # Account ID
    identity = sts.get_caller_identity()
    account_id = identity["Account"]

    data = IAMData(account_id=account_id, region=region)

    # ── Users ───────────────────────────────────────────────────────────────
    logger.info("Coletando IAM users...")
    for user in _paginate(iam, "list_users"):
        user_name = user["UserName"]
        policies = []
        attached = iam.list_attached_user_policies(UserName=user_name).get("AttachedManagedPolicies", [])
        for ap in attached:
            ver = iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]
            default_version = iam.get_policy_version(
                PolicyArn=ap["PolicyArn"],
                VersionId=ver["DefaultVersionId"],
            )["PolicyVersion"]["Document"]
            policies.append({"name": ap["PolicyName"], "arn": ap["PolicyArn"], "document": default_version})

        inline = iam.list_user_policies(UserName=user_name).get("UserPolicies", [])
        for idx, pol_name in enumerate(inline):
            doc = iam.get_user_policy(UserName=user_name, PolicyName=pol_name)["PolicyDocument"]
            policies.append({"name": pol_name, "inline": True, "document": doc})

        user_tags = iam.list_user_tags(UserName=user_name).get("Tags", [])

        data.users.append({
            "name": user_name,
            "arn": user["Arn"],
            "created": user.get("CreateDate"),
            "password_last_used": user.get("PasswordLastUsed"),
            "access_keys": iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []),
            "mfa": iam.list_mfa_devices(UserName=user_name).get("MFADevices", []),
            "policies": policies,
            "tags": user_tags,
        })

    # ── Roles ──────────────────────────────────────────────────────────────
    logger.info("Coletando IAM roles...")
    for role in _paginate(iam, "list_roles"):
        role_name = role["RoleName"]
        role_policies = []

        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedManagedPolicies", [])
        for ap in attached:
            ver = iam.get_policy_version(
                PolicyArn=ap["PolicyArn"],
                VersionId=iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"],
            )["PolicyVersion"]["Document"]
            role_policies.append({"name": ap["PolicyName"], "arn": ap["PolicyArn"], "document": ver})

        inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        for pol_name in inline:
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)["PolicyDocument"]
            role_policies.append({"name": pol_name, "inline": True, "document": doc})

        # Trust policy (assume role policy)
        trust = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]

        role_tags = iam.list_role_tags(RoleName=role_name).get("Tags", [])

        data.roles.append({
            "name": role_name,
            "arn": role["Arn"],
            "created": role.get("CreateDate"),
            "max_session": role.get("MaxSessionDuration"),
            "policies": role_policies,
            "trust_policy": trust,
            "tags": role_tags,
        })

    # ── Groups ─────────────────────────────────────────────────────────────
    logger.info("Coletando IAM groups...")
    for group in _paginate(iam, "list_groups"):
        group_name = group["GroupName"]
        policies = []
        for ap in iam.list_attached_group_policies(GroupName=group_name).get("AttachedManagedPolicies", []):
            ver = iam.get_policy_version(
                PolicyArn=ap["PolicyArn"],
                VersionId=iam.get_policy(PolicyArn=ap["PolicyArn"])["Policy"]["DefaultVersionId"],
            )["PolicyVersion"]["Document"]
            policies.append({"name": ap["PolicyName"], "document": ver})

        inline = iam.list_group_policies(GroupName=group_name).get("PolicyNames", [])
        for pol_name in inline:
            doc = iam.get_group_policy(GroupName=group_name, PolicyName=pol_name)["PolicyDocument"]
            policies.append({"name": pol_name, "inline": True, "document": doc})

        members = [
            m["UserName"]
            for m in _paginate(iam, "list_users_in_group", GroupName=group_name)
        ]

        data.groups.append({
            "name": group_name,
            "arn": group["Arn"],
            "created": group.get("CreateDate"),
            "policies": policies,
            "members": members,
        })

    # ── Managed Policies ───────────────────────────────────────────────────
    logger.info("Coletando managed policies (apenas locais da conta)...")
    for policy in _paginate(iam, "list_policies", Scope="Local"):
        data.policies.append({
            "name": policy["PolicyName"],
            "arn": policy["Arn"],
            "default_version": policy.get("DefaultVersionId"),
            "attachment_count": policy.get("AttachmentCount", 0),
        })

    logger.info(
        f"Coletado: {len(data.users)} users, {len(data.roles)} roles, "
        f"{len(data.groups)} groups, {len(data.policies)} managed policies"
    )
    return data
