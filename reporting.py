"""Geração de relatórios CSV, Excel e PDF a partir das consultas analíticas."""

from __future__ import annotations

import csv
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from analytics import (
    CHANGE_EVENT_TYPES,
    QueryFilters,
    fetch_availability,
    fetch_events,
    fetch_inventory,
    fetch_top_disconnects,
)


def report_datasets(
    connection: Any, report_type: str, filters: QueryFilters
) -> dict[str, list[dict[str, Any]]]:
    if report_type == "inventario":
        return {"inventario": fetch_inventory(connection, filters)}
    if report_type == "eventos":
        return {"eventos": fetch_events(connection, filters)}
    if report_type == "disponibilidade":
        return {"disponibilidade": fetch_availability(connection, filters)}
    if report_type == "desconexoes":
        return {"desconexoes": fetch_top_disconnects(connection, filters)}
    if report_type == "alteracoes":
        return {"alteracoes": fetch_events(connection, filters, event_types=CHANGE_EVENT_TYPES)}
    if report_type == "completo":
        return {
            "inventario": fetch_inventory(connection, filters),
            "eventos": fetch_events(connection, filters),
            "disponibilidade": fetch_availability(connection, filters),
            "desconexoes": fetch_top_disconnects(connection, filters),
        }
    raise ValueError(f"tipo de relatório desconhecido: {report_type}")


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "relatorio"


def _serializable(value: Any) -> Any:
    return value.isoformat(sep=" ", timespec="seconds") if isinstance(value, datetime) else value


def _safe_spreadsheet_value(value: Any) -> Any:
    """Impede que texto controlado pela rede seja interpretado como fórmula."""

    value = _serializable(value)
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


def _base_path(output_dir: str | Path, report_type: str, generated_at: datetime) -> Path:
    directory = Path(output_dir) / generated_at.strftime("%Y") / generated_at.strftime("%m")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{_safe_name(report_type)}_{generated_at:%Y%m%d_%H%M%S}"


def export_csv(
    datasets: dict[str, list[dict[str, Any]]], base_path: Path
) -> tuple[Path, ...]:
    paths: list[Path] = []
    for name, rows in datasets.items():
        path = base_path.with_name(f"{base_path.name}_{_safe_name(name)}.csv")
        fields = list(rows[0]) if rows else ["message"]
        with path.open("w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            if rows:
                writer.writerows(
                    {key: _safe_spreadsheet_value(value) for key, value in row.items()} for row in rows
                )
            else:
                writer.writerow({"message": "Nenhum registro encontrado"})
        paths.append(path)
    return tuple(paths)


def export_excel(datasets: dict[str, list[dict[str, Any]]], base_path: Path) -> tuple[Path, ...]:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError as exc:
        raise RuntimeError("instale openpyxl com: python -m pip install -r requirements.txt") from exc

    workbook = Workbook()
    workbook.remove(workbook.active)
    for name, rows in datasets.items():
        sheet = workbook.create_sheet(title=name[:31])
        fields = list(rows[0]) if rows else ["message"]
        sheet.append(fields)
        for cell in sheet[1]:
            cell.font = Font(bold=True)
        if rows:
            for row in rows:
                sheet.append([_safe_spreadsheet_value(row.get(field)) for field in fields])
        else:
            sheet.append(["Nenhum registro encontrado"])
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
    path = base_path.with_suffix(".xlsx")
    workbook.save(path)
    return (path,)


def export_pdf(datasets: dict[str, list[dict[str, Any]]], base_path: Path) -> tuple[Path, ...]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("instale reportlab com: python -m pip install -r requirements.txt") from exc

    path = base_path.with_suffix(".pdf")
    document = SimpleDocTemplate(str(path), pagesize=landscape(A4), leftMargin=24, rightMargin=24)
    styles = getSampleStyleSheet()
    elements: list[Any] = []
    for index, (name, rows) in enumerate(datasets.items()):
        if index:
            elements.append(PageBreak())
        elements.append(Paragraph(name.replace("_", " ").title(), styles["Heading1"]))
        fields = list(rows[0]) if rows else ["message"]
        data = [fields]
        if rows:
            data.extend(
                [str(_serializable(row.get(field)) or "")[:60] for field in fields]
                for row in rows
            )
        else:
            data.append(["Nenhum registro encontrado"])
        table = Table(data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(table)
    document.build(elements)
    return (path,)


def generate_report(
    connection: Any,
    report_type: str,
    output_format: str,
    filters: QueryFilters,
    output_dir: str | Path = "relatorios",
    *,
    generated_at: datetime | None = None,
) -> tuple[Path, ...]:
    generated_at = generated_at or datetime.now()
    datasets = report_datasets(connection, report_type, filters)
    base_path = _base_path(output_dir, report_type, generated_at)
    exporters = {"csv": export_csv, "xlsx": export_excel, "pdf": export_pdf}
    try:
        exporter = exporters[output_format]
    except KeyError as exc:
        raise ValueError(f"formato desconhecido: {output_format}") from exc
    return exporter(datasets, base_path)


def next_scheduled_time(now: datetime, frequency: str) -> datetime:
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if frequency == "diario":
        return midnight + timedelta(days=1)
    if frequency == "semanal":
        days = 7 - now.weekday()
        return midnight + timedelta(days=days or 7)
    if frequency == "mensal":
        if now.month == 12:
            return midnight.replace(year=now.year + 1, month=1, day=1)
        return midnight.replace(month=now.month + 1, day=1)
    raise ValueError(f"frequência desconhecida: {frequency}")
