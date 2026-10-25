"""Configuração da API carregada exclusivamente no ambiente do processo."""

from __future__ import annotations

import os
from dataclasses import dataclass

import config


def _boolean(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "sim"}


@dataclass(frozen=True)
class APISettings:
    environment: str
    docs_enabled: bool
    cors_origins: tuple[str, ...]
    mysql: dict[str, object]
    pool_size: int
    report_directory: str


def load_settings() -> APISettings:
    environment = os.getenv("NETWORK_MAPPER_API_ENV", "development").lower()
    docs_default = environment != "production"
    origins = tuple(
        origin.strip()
        for origin in os.getenv("NETWORK_MAPPER_API_CORS_ORIGINS", "").split(",")
        if origin.strip()
    )
    pool_size = int(os.getenv("NETWORK_MAPPER_API_DB_POOL_SIZE", "5"))
    if not 1 <= pool_size <= 32:
        raise ValueError("NETWORK_MAPPER_API_DB_POOL_SIZE deve estar entre 1 e 32")
    return APISettings(
        environment=environment,
        docs_enabled=_boolean("NETWORK_MAPPER_API_DOCS_ENABLED", docs_default),
        cors_origins=origins,
        mysql={
            "host": os.getenv("NETWORK_MAPPER_DB_HOST", config.MYSQL_HOST),
            "port": int(os.getenv("NETWORK_MAPPER_DB_PORT", str(config.MYSQL_PORT))),
            "user": os.getenv("NETWORK_MAPPER_DB_USER", config.MYSQL_USER),
            "password": os.getenv("NETWORK_MAPPER_DB_PASSWORD", config.MYSQL_PASSWORD),
            "database": os.getenv("NETWORK_MAPPER_DB_NAME", config.MYSQL_DATABASE),
            "connection_timeout": 10,
        },
        pool_size=pool_size,
        report_directory=os.getenv("NETWORK_MAPPER_API_REPORT_DIR", "relatorios_api"),
    )
