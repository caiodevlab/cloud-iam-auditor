"""
Analisador principal — orquestra coleta + análise de regras.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from iam_auditor.collector import IAMData, collect_iam
from iam_auditor.config import AuditorConfig, load_config
from iam_auditor.rules import Issue, Severity, analyze_iam_object

logger = logging.getLogger(__name__)


@dataclass
class AuditReport:
    """Relatório final de auditoria."""
    account_id: str
    region: str
    issues: list[Issue] = field(default_factory=list)

    @property
    def critical(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == Severity.CRITICAL]

    @property
    def high(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == Severity.HIGH]

    @property
    def medium(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == Severity.MEDIUM]

    @property
    def low(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == Severity.LOW]

    def total(self) -> int:
        return len(self.issues)


def run_audit(
    profile: Optional[str] = None,
    region: str = "us-east-1",
    config: AuditorConfig | None = None,
) -> AuditReport:
    """
    Orquestra: coleta dados IAM + análise de regras + filtro de severidade.
    """
    config = config or load_config()

    logger.info(f"Iniciando auditoria — profile={profile}, region={region}")
    data = collect_iam(profile=profile, region=region)
    report = AuditReport(account_id=data.account_id, region=data.region)

    suppress = config.suppress

    # ── Analisa users ────────────────────────────────────────────────────────
    for user in data.users:
        issues = analyze_iam_object(
            name=user["name"],
            obj_type="user",
            inline_policies=[p["document"] for p in user.get("policies", []) if p.get("document")],
            tags=user.get("tags"),
            suppress_patterns=suppress.users,
        )
        # Adiciona info extra nos issues
        for iss in issues.issues:
            iss.resource_name = f"{user['name']} (user)"
            report.issues.append(iss)

        # Check: múltiplas access keys
        if len(user.get("access_keys", [])) > 1:
            report.issues.append(Issue(
                severity=Severity.MEDIUM,
                rule_id="MULTIPLE_ACCESS_KEYS",
                title="Múltiplas access keys",
                detail=f"Usuário {user['name']} tem {len(user['access_keys'])} access keys ativas.",
                resource_type="user",
                resource_name=user["name"],
                recommendation="Revise se realmente precisa de mais de uma access key. Remova as inativas.",
            ))

        # Check: sem MFA
        if not user.get("mfa"):
            report.issues.append(Issue(
                severity=Severity.MEDIUM,
                rule_id="NO_MFA",
                title="Usuário sem MFA",
                detail=f"Usuário {user['name']} não tem MFA configurado.",
                resource_type="user",
                resource_name=user["name"],
                recommendation="Ative MFA para todos os usuários IAM. Use MFA virtual ou hardware key.",
            ))

    # ── Analisa roles ───────────────────────────────────────────────────────
    for role in data.roles:
        issues = analyze_iam_object(
            name=role["name"],
            obj_type="role",
            inline_policies=[p["document"] for p in role.get("policies", []) if p.get("document")],
            trust_policy=role.get("trust_policy"),
            tags=role.get("tags"),
            suppress_patterns=suppress.roles,
        )
        for iss in issues.issues:
            iss.resource_name = f"{role['name']} (role)"
            report.issues.append(iss)

    # ── Analisa groups ────────────────────────────────────────────────────────
    for group in data.groups:
        issues = analyze_iam_object(
            name=group["name"],
            obj_type="group",
            inline_policies=[p["document"] for p in group.get("policies", []) if p.get("document")],
            suppress_patterns=suppress.groups,
        )
        for iss in issues.issues:
            iss.resource_name = f"{group['name']} (group)"
            report.issues.append(iss)

        if not group.get("members"):
            report.issues.append(Issue(
                severity=Severity.LOW,
                rule_id="EMPTY_GROUP",
                title="Grupo vazio",
                detail=f"Grupo {group['name']} não tem membros.",
                resource_type="group",
                resource_name=group["name"],
                recommendation="Remova grupos vazios para simplificar gestão IAM.",
            ))

    logger.info(
        f"Auditoria concluída: {report.total()} issues "
        f"(CRITICAL={len(report.critical)} HIGH={len(report.high)} "
        f"MEDIUM={len(report.medium)} LOW={len(report.low)})"
    )
    return report
