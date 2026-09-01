"""Configuração do auditor: perfil, região, suppress list."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field


class SuppressConfig(BaseModel):
    """Recursos a ignorar na análise."""
    roles: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    policies: list[str] = Field(default_factory=list)


class AuditorConfig(BaseModel):
    """Configuração global do auditor."""
    suppress: SuppressConfig = Field(default_factory=SuppressConfig)
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    severity_threshold: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL


def load_config() -> AuditorConfig:
    """
    Carrega configuração de ~/.iam_auditor/config.yaml se existir.
    Caso contrário retorna defaults.
    """
    config_path = Path.home() / ".iam_auditor" / "config.yaml"
    if not config_path.exists():
        return AuditorConfig()

    with open(config_path) as f:
        data = yaml.safe_load(f) or {}

    return AuditorConfig.model_validate(data)


def matches_pattern(name: str, patterns: list[str]) -> bool:
    """Verifica se 'name' casa com algum dos padrões (suporte a *)."""
    import fnmatch
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)
