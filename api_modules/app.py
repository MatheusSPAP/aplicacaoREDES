"""Aplicação FastAPI independente do scanner Network Mapper."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import APISettings, load_settings
from .database import DatabasePool, connection_dependency
from .routes import create_router


logger = logging.getLogger("network_mapper.api")


def create_app(
    settings: APISettings | None = None,
    *,
    connection_provider: Any | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    pool = DatabasePool(settings)

    def database_connection() -> Iterator[Any]:
        yield from connection_dependency(pool)

    provider = connection_provider or database_connection

    app = FastAPI(
        title="Network Mapper API",
        version="1.0.0",
        description="API somente leitura para inventário e histórico de rede.",
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.database_pool = pool
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET"],
            allow_headers=["Accept"],
        )

    router = create_router(provider)
    app.include_router(router)

    @app.exception_handler(Exception)
    async def unhandled_error(_request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, HTTPException):
            raise exc
        # Não inclui a mensagem da exceção: conectores podem acrescentar host ou
        # usuário aos detalhes de falhas de autenticação.
        logger.error("Falha interna na API (%s)", type(exc).__name__)
        return JSONResponse(status_code=503, content={"detail": "Serviço temporariamente indisponível"})

    return app


app = create_app()
