"""CLI do Cloud IAM Auditor via Click."""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iam_auditor.analyzer import AuditReport, run_audit
from iam_auditor.config import load_config
from iam_auditor.rules import Severity

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Cloud IAM Auditor — audite permissões IAM na AWS."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command("audit")
@click.option("--profile", default=None, help="Perfil AWS (usa default se omitido)")
@click.option("--region", default="us-east-1", help="Região AWS")
@click.option("--output", "-o", multiple=True, type=click.Path(), help="Arquivo de saída (pode usar -o várias vezes)")
@click.option(
    "--severity",
    default="LOW",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    help="Incluir só issues desta severidade ou acima",
)
@click.option("--dry-run", is_flag=True, help="Simula sem conectar na AWS")
def audit(profile, region, output, severity, dry_run):
    """Executa auditoria IAM completa."""
    if dry_run:
        console.print("[yellow]Modo dry-run: simulando sem conectar na AWS[/yellow]")
        console.print("  [dim]O scan real mostraria: users, roles, groups, policies[/dim]")
        return

    config = load_config()
    console.print(f"[blue]Auditando IAM — profile={profile or 'default'}, region={region}[/blue]")

    try:
        report = run_audit(profile=profile, region=region, config=config)
    except Exception as exc:
        console.print(f"[red]Erro: {exc}[/red]")
        console.print("[dim]Verifique suas credenciais AWS: aws configure --profile <nome>[/dim]")
        sys.exit(1)

    # Filtra por severidade
    severity_order = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
    threshold = severity_order.get(Severity(severity.upper()), 0)
    filtered = [
        i for i in report.issues
        if severity_order.get(i.severity, 0) >= threshold
    ]

    # ── Painel de resumo ────────────────────────────────────────────────────
    summary_text = (
        f"[bold]Account:[/bold] {report.account_id}\n"
        f"[bold]Região:[/bold] {report.region}\n"
        f"[bold]Issues:[/bold] {len(filtered)}\n"
        f"  🔴 CRITICAL: {sum(1 for i in filtered if i.severity == Severity.CRITICAL)}\n"
        f"  🟠 HIGH:     {sum(1 for i in filtered if i.severity == Severity.HIGH)}\n"
        f"  🟡 MEDIUM:   {sum(1 for i in filtered if i.severity == Severity.MEDIUM)}\n"
        f"  🔵 LOW:      {sum(1 for i in filtered if i.severity == Severity.LOW)}\n"
    )
    console.print(Panel(summary_text, title="[bold]IAM Auditor — Resumo[/bold]", expand=False))

    # ── Tabela de issues ───────────────────────────────────────────────────
    if filtered:
        table = Table(title="Issues Encontrados", show_lines=True)
        table.add_column("Sev.", style="bold")
        table.add_column("Recurso")
        table.add_column("Título")
        table.add_column("Recomendação")

        sev_emoji = {
            Severity.CRITICAL: "[red]CRITICAL[/red]",
            Severity.HIGH: "[orange1]HIGH[/orange1]",
            Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
            Severity.LOW: "[blue]LOW[/blue]",
        }
        for iss in filtered:
            table.add_row(
                sev_emoji[iss.severity],
                iss.resource_name,
                iss.title,
                iss.recommendation[:60] + "..." if len(iss.recommendation) > 60 else iss.recommendation,
            )
        console.print(table)
    else:
        console.print("[green]✅ Nenhum issue encontrado![/green]")

    # ── Exportar JSON ───────────────────────────────────────────────────────
    for out_file in output:
        path = Path(out_file)
        report_dict = {
            "account_id": report.account_id,
            "region": report.region,
            "total_issues": len(filtered),
            "summary": {
                "critical": len(report.critical),
                "high": len(report.high),
                "medium": len(report.medium),
                "low": len(report.low),
            },
            "issues": [
                {
                    "severity": i.severity.value,
                    "rule_id": i.rule_id,
                    "title": i.title,
                    "detail": i.detail,
                    "resource": i.resource_name,
                    "recommendation": i.recommendation,
                }
                for i in filtered
            ],
        }
        with open(path, "w") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✅ Relatório salvo em {path}[/green]")


@cli.command("check-profile")
@click.option("--profile", prompt=True, help="Nome do perfil AWS")
def check_profile(profile):
    """Verifica se um perfil AWS está configurado corretamente."""
    import botocore.exceptions
    import boto3
    try:
        sess = boto3.Session(profile_name=profile)
        creds = sess.get_credentials()
        console.print(f"[green]✅ Perfil '{profile}' OK[/green]")
        console.print(f"  Access Key: ...{creds.access_key[-4:]}")
        console.print(f"  Region:     {sess.region_name or 'não definida'}")
    except botocore.exceptions.ProfileNotFound:
        console.print(f"[red]❌ Perfil '{profile}' não encontrado. Rode: aws configure --profile {profile}[/red]")


if __name__ == "__main__":
    cli()
