"""Rotas REST somente leitura do Network Mapper."""

from __future__ import annotations

import ipaddress
import shutil
import tempfile
import zipfile
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from analytics import (
    INVENTORY_EVENT_TYPES,
    PRESENCE_EVENT_TYPES,
    QueryFilters,
    fetch_availability,
    fetch_device_ports,
    fetch_events,
    fetch_inventory,
    fetch_networks,
    fetch_top_disconnects,
    parse_datetime,
)
from api_models import DataResponse, HealthResponse, PaginatedResponse
from mysql_storage import get_device_history, normalize_mac
from reporting import generate_report, report_datasets


EventType = Literal[
    "NEW", "OFFLINE", "RECONNECTED", "IP_CHANGED", "HOSTNAME_DISCOVERED",
    "HOSTNAME_CHANGED", "PORT_OPENED", "PORT_CLOSED", "SERVICE_CHANGED",
]
ReportType = Literal[
    "inventario", "eventos", "alteracoes", "desconexoes", "disponibilidade", "completo"
]
ReportFormat = Literal["json", "csv", "xlsx", "pdf"]


def _normalize_network(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_network(value, strict=False).with_prefixlen
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Rede CIDR invÃ¡lida") from exc


def _normalize_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="EndereÃ§o IP invÃ¡lido") from exc


def _normalize_mac(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return normalize_mac(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="EndereÃ§o MAC invÃ¡lido") from exc


def query_filters(
    ip: Annotated[str | None, Query(description="IPv4/IPv6 atual ou histÃ³rico")] = None,
    mac: Annotated[str | None, Query(description="EndereÃ§o MAC")] = None,
    network: Annotated[str | None, Query(description="Rede em formato CIDR")] = None,
    status_filter: Annotated[Literal["online", "offline"] | None, Query(alias="status")] = None,
    start: Annotated[str | None, Query(alias="start_date", description="AAAA-MM-DD ou data/hora")] = None,
    end: Annotated[str | None, Query(alias="end_date", description="AAAA-MM-DD ou data/hora")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> QueryFilters:
    try:
        start_at = parse_datetime(start)
        end_at = parse_datetime(end, end_of_day=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if start_at and end_at and start_at > end_at:
        raise HTTPException(status_code=422, detail="start_date deve ser anterior a end_date")
    return QueryFilters(
        network=_normalize_network(network),
        mac=_normalize_mac(mac),
        ip=_normalize_ip(ip),
        status=status_filter,
        start=start_at,
        end=end_at,
        limit=limit,
        offset=(page - 1) * limit,
    )


def _page(rows: list[dict[str, Any]], filters: QueryFilters) -> dict[str, Any]:
    return {
        "data": rows,
        "pagination": {
            "page": filters.offset // filters.limit + 1,
            "limit": filters.limit,
            "returned": len(rows),
        },
    }


def create_router(connection_provider: Any) -> APIRouter:
    router = APIRouter(prefix="/api/v1")

    @router.get("/devices", response_model=PaginatedResponse, summary="Listar dispositivos")
    def devices(filters: QueryFilters = Depends(query_filters), connection: Any = Depends(connection_provider)) -> dict[str, Any]:
        return _page(fetch_inventory(connection, filters), filters)

    @router.get("/devices/{mac}/ports", response_model=DataResponse, summary="Portas e serviÃ§os")
    def device_ports(
        mac: str,
        connection: Any = Depends(connection_provider),
        network: Annotated[str | None, Query(description="Rede CIDR")] = None,
    ) -> dict[str, Any]:
        normalized = _normalize_mac(mac)
        rows = fetch_device_ports(connection, normalized or "", _normalize_network(network))
        if not rows and get_device_history(connection, normalized or "", _normalize_network(network)) is None:
            raise HTTPException(status_code=404, detail="Dispositivo nÃ£o encontrado")
        return {"data": rows}

    @router.get("/devices/{mac}", response_model=DataResponse, summary="Detalhes e histÃ³rico")
    def device_detail(
        mac: str,
        connection: Any = Depends(connection_provider),
        network: Annotated[str | None, Query(description="Rede CIDR")] = None,
    ) -> dict[str, Any]:
        history = get_device_history(connection, _normalize_mac(mac) or "", _normalize_network(network))
        if history is None:
            raise HTTPException(status_code=404, detail="Dispositivo nÃ£o encontrado")
        return {"data": asdict(history)}

    @router.get("/networks", response_model=DataResponse, summary="Listar redes monitoradas")
    def networks(connection: Any = Depends(connection_provider)) -> dict[str, Any]:
        return {"data": fetch_networks(connection)}

    @router.get("/events", response_model=PaginatedResponse, summary="Consultar eventos")
    def events(
        filters: QueryFilters = Depends(query_filters),
        connection: Any = Depends(connection_provider),
        event_type: Annotated[EventType | None, Query(description="Tipo exato do evento")] = None,
    ) -> dict[str, Any]:
        types = {event_type} if event_type else None
        return _page(fetch_events(connection, filters, event_types=types), filters)

    @router.get("/availability", response_model=PaginatedResponse, summary="Disponibilidade")
    def availability(filters: QueryFilters = Depends(query_filters), connection: Any = Depends(connection_provider)) -> dict[str, Any]:
        return _page(fetch_availability(connection, filters), filters)

    @router.get("/disconnections", response_model=PaginatedResponse, summary="Mais desconexÃµes")
    def disconnections(filters: QueryFilters = Depends(query_filters), connection: Any = Depends(connection_provider)) -> dict[str, Any]:
        return _page(fetch_top_disconnects(connection, filters), filters)

    @router.get("/reports", summary="Dados ou arquivo de relatÃ³rio")
    def reports(
        filters: QueryFilters = Depends(query_filters),
        connection: Any = Depends(connection_provider),
        report_type: Annotated[ReportType, Query(description="ConteÃºdo do relatÃ³rio")] = "completo",
        output_format: Annotated[ReportFormat, Query(alias="format")] = "json",
        event_type: Annotated[EventType | None, Query(description="Tipo exato do evento")] = None,
    ) -> Any:
        event_types = {event_type} if event_type else None
        if output_format == "json":
            return {
                "data": report_datasets(
                    connection, report_type, filters, event_types=event_types
                )
            }
        temporary = Path(tempfile.mkdtemp(prefix="network_mapper_api_"))
        try:
            paths = generate_report(
                connection,
                report_type,
                output_format,
                filters,
                temporary,
                event_types=event_types,
            )
            if len(paths) == 1:
                path = paths[0]
                media_types = {
                    "csv": "text/csv",
                    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "pdf": "application/pdf",
                }
                return FileResponse(
                    path,
                    media_type=media_types[output_format],
                    filename=path.name,
                    background=BackgroundTask(shutil.rmtree, temporary, ignore_errors=True),
                )
            archive = temporary / f"{report_type}_{datetime.now():%Y%m%d_%H%M%S}.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                for path in paths:
                    bundle.write(path, arcname=path.name)
            return FileResponse(
                archive,
                media_type="application/zip",
                filename=archive.name,
                background=BackgroundTask(shutil.rmtree, temporary, ignore_errors=True),
            )
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    @router.get("/health", response_model=HealthResponse, summary="SaÃºde da API e banco")
    def health(connection: Any = Depends(connection_provider)) -> dict[str, str]:
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        finally:
            cursor.close()
        return {"status": "ok", "database": "connected"}

    return router

