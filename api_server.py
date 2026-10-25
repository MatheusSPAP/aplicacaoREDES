"""Inicializador da API usando host e porta definidos por ambiente."""

from __future__ import annotations

import os

import uvicorn


if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host=os.getenv("NETWORK_MAPPER_API_HOST", "127.0.0.1"),
        port=int(os.getenv("NETWORK_MAPPER_API_PORT", "8000")),
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("NETWORK_MAPPER_API_FORWARDED_ALLOW_IPS", "127.0.0.1"),
    )
