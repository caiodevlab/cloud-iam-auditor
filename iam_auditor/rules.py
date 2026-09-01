"""
Regras de detecção de problemas IAM.
Cada regra retorna uma lista de Issues se encontrar violação.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Issue:
    severity: Severity
    rule_id: str
    title: str
    detail: str
    resource_type: str  # "user" | "role" | "group" | "policy"
    resource_name: str
    recommendation: str


# ── Padrões dangerous ─────────────────────────────────────────────────────────
WILDCARD_ACTION_RE = re.compile(r'"Action"\s*:\s*\[?"\*"?\]?"?')
FULL_ACCESS_RE = re.compile(r"FullAccess|AdministratorAccess|PowerUserAccess")
PASSROLE_RE = re.compile(r"iam:PassRole", re.IGNORECASE)
STAR_RE = re.compile(r'"Resource"\s*:\s*\[?"\*"?\]?"?')
TRUST_STAR_RE = re.compile(r'"Principal"\s*:\s*\{?\s*"\*"\s*\}?')
GET_CREDENTIALS = re.compile(r"Get.*Credential|Iam.*PassRole", re.IGNORECASE)


@dataclass
class RuleResult:
    issues: list[Issue] = field(default_factory=list)
    clean: bool = True

    def add(self, issue: Issue) -> None:
        self.issues.append(issue)
        self.clean = False


def analyze_policy(policy: dict, resource_name: str, resource_type: str) -> RuleResult:
    """
    Analisa uma policy dict (já parseado de JSON) e retorna issues.
    """
    result = RuleResult()
    policy_str = json.dumps(policy, separators=(",", ":"))

    # ── CRITICAL: Action: "*" ──────────────────────────────────────────────
    if WILDCARD_ACTION_RE.search(policy_str):
        result.add(Issue(
            severity=Severity.CRITICAL,
            rule_id="WILDCARD_ACTION",
            title="Wildcard em Action",
            detail=f"Policy contém Action: '*' — viola princípio de menor privilégio.",
            resource_type=resource_type,
            resource_name=resource_name,
            recommendation="Substitua '*' por ações específicas que o recurso realmente precisa.",
        ))

    # ── CRITICAL: Resource: "*" ─────────────────────────────────────────────
    if STAR_RE.search(policy_str):
        result.add(Issue(
            severity=Severity.HIGH,
            rule_id="WILDCARD_RESOURCE",
            title="Wildcard em Resource",
            detail="Policy permite acesso a qualquer recurso ('*').",
            resource_type=resource_type,
            resource_name=resource_name,
            recommendation="Restrinja Resource aos ARNs específicos que precisam de acesso.",
        ))

    # ── HIGH: PassRole sem serviço restrito ────────────────────────────────
    if PASSROLE_RE.search(policy_str):
        # Se não há restrictive service constraint
        if "NotAction" not in policy_str and "Condition" not in policy_str:
            result.add(Issue(
                severity=Severity.HIGH,
                rule_id="UNRESTRICTED_PASSROLE",
                title="PassRole irrestrito",
                detail="iam:PassRole sem restrição de serviço destino.",
                resource_type=resource_type,
                resource_name=resource_name,
                recommendation="Adicione Condition限定 o serviço que pode receber a role (ex: ec2, lambda).",
            ))

    # ── HIGH: FullAccess / Admin ───────────────────────────────────────────
    if FULL_ACCESS_RE.search(policy_str):
        result.add(Issue(
            severity=Severity.HIGH,
            rule_id="EXCESSIVE_ACCESS",
            title="Política com acesso total",
            detail="Policy anexa acesso total (*FullAccess ou AdministratorAccess).",
            resource_type=resource_type,
            resource_name=resource_name,
            recommendation="Revise se realmente precisa de acesso total. Preferencialmente use políticas customizadas com ações mínimas.",
        ))

    return result


def analyze_trust_policy(trust_policy: dict, role_name: str) -> RuleResult:
    """Analisa a trust policy de uma role (quem pode assumi-la)."""
    result = RuleResult()
    trust_str = json.dumps(trust_policy, separators=(",", ":"))

    # ── CRITICAL: Principal: "*" na trust policy ────────────────────────────
    if TRUST_STAR_RE.search(trust_str):
        result.add(Issue(
            severity=Severity.CRITICAL,
            rule_id="PUBLIC_TRUST",
            title="Trust policy pública",
            detail=f"Role {role_name} pode ser assumida por qualquer principal (*).",
            resource_type="role",
            resource_name=role_name,
            recommendation="Restrinja o Principal a accounts ou services específicos. Remova '*'.",
        ))

    # ── MEDIUM: Confuso — serviço e account juntos ─────────────────────────
    principal = trust_policy.get("Statement", [{}])[0].get("Principal", {})
    if isinstance(principal, dict) and "AWS" in principal:
        aws_principal = principal["AWS"]
        # Qualquer ARN que comece com arn:aws:iam:: sem ser da própria conta é cross-account
        # (isso pode ser legítimo mas merece atenção)
        pass  # mais detecção pode ser adicionada

    return result


def analyze_iam_object(
    name: str,
    obj_type: str,
    inline_policies: list[dict] | None = None,
    attached_managed_policies: list[str] | None = None,
    trust_policy: dict | None = None,
    tags: list[dict] | None = None,
    suppress_patterns: list[str] | None = None,
) -> RuleResult:
    """
    Analisa um principal IAM completo (user, role, group) e retorna todos os issues.
    """
    result = RuleResult()

    # ── Suppress check ─────────────────────────────────────────────────────
    if suppress_patterns:
        if any(fnmatch.fnmatch(name, p) for p in suppress_patterns):
            return result  # suppressed — retorna limpo

    # ── Inline policies ─────────────────────────────────────────────────────
    for idx, policy in enumerate(inline_policies or []):
        r = analyze_policy(policy, f"{name}/inline-policy-{idx+1}", obj_type)
        result.issues.extend(r.issues)

    # ── Trust policy (só para roles) ───────────────────────────────────────
    if trust_policy:
        r = analyze_trust_policy(trust_policy, name)
        result.issues.extend(r.issues)

    return result
