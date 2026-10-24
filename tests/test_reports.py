"""Testes de análises e relatórios sem acessar o MySQL real."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from analytics import calculate_availability, estimate_availability, parse_datetime
from reporting import export_csv, export_excel, export_pdf, next_scheduled_time


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = {
            "inventario": [
                {
                    "network": "192.168.1.0/24",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "ip": "192.168.1.10",
                    "hostname": "printer.local",
                    "status": "online",
                }
            ]
        }

    def test_parse_date_end_includes_whole_day(self) -> None:
        parsed = parse_datetime("2026-10-24", end_of_day=True)
        self.assertEqual(parsed, datetime(2026, 10, 24, 23, 59, 59, 999999))

    def test_estimated_availability_is_labeled_interval_calculation(self) -> None:
        start = datetime(2026, 1, 1, 0, 0)
        end = datetime(2026, 1, 1, 10, 0)
        events = [
            {"event_type": "OFFLINE", "occurred_at": datetime(2026, 1, 1, 4, 0)},
            {"event_type": "RECONNECTED", "occurred_at": datetime(2026, 1, 1, 6, 0)},
        ]
        self.assertEqual(
            estimate_availability(events, start, end, initially_online=True), 80.0
        )

    def test_offline_before_period_is_not_reported_as_100_percent(self) -> None:
        start = datetime(2026, 1, 1, 10, 0)
        end = datetime(2026, 1, 1, 10, 10)
        scans = [datetime(2026, 1, 1, 10, minute) for minute in range(11)]
        result = calculate_availability(
            [{"event_type": "RECONNECTED", "occurred_at": datetime(2026, 1, 1, 10, 5)}],
            scans, start, end, initial_state="offline",
        )
        self.assertEqual(result["estimated_percent"], 50.0)

    def test_period_without_monitoring_is_unknown(self) -> None:
        start = datetime(2026, 1, 1, 0, 0)
        end = datetime(2026, 1, 1, 2, 0)
        result = calculate_availability([], [], start, end, initial_state="online")
        self.assertIsNone(result["estimated_percent"])
        self.assertEqual(result["monitoring_coverage_percent"], 0.0)
        self.assertEqual(result["unknown_seconds"], 7200.0)

    def test_long_monitoring_gap_is_unknown(self) -> None:
        start = datetime(2026, 1, 1, 0, 0)
        end = datetime(2026, 1, 1, 1, 2)
        scans = [
            datetime(2026, 1, 1, 0, 0), datetime(2026, 1, 1, 0, 1),
            datetime(2026, 1, 1, 1, 1), datetime(2026, 1, 1, 1, 2),
        ]
        result = calculate_availability([], scans, start, end, initial_state="online")
        self.assertLess(result["monitoring_coverage_percent"], 5.0)
        self.assertGreater(result["unknown_seconds"], 3500)

    def test_schedule_boundaries(self) -> None:
        now = datetime(2026, 10, 24, 14, 30)  # sábado
        self.assertEqual(next_scheduled_time(now, "diario"), datetime(2026, 10, 25))
        self.assertEqual(next_scheduled_time(now, "semanal"), datetime(2026, 10, 26))
        self.assertEqual(next_scheduled_time(now, "mensal"), datetime(2026, 11, 1))

    def test_csv_export_uses_organized_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "2026" / "10" / "report"
            base.parent.mkdir(parents=True)
            paths = export_csv(self.rows, base)
            self.assertEqual(len(paths), 1)
            self.assertTrue(paths[0].exists())
            self.assertIn("printer.local", paths[0].read_text(encoding="utf-8-sig"))

    def test_csv_escapes_formula_injection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rows = {"inventario": [{"hostname": "=HYPERLINK(\"bad\")"}]}
            path = export_csv(rows, Path(directory) / "report")[0]
            self.assertIn("'=HYPERLINK", path.read_text(encoding="utf-8-sig"))

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl ausente")
    def test_excel_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = export_excel(self.rows, Path(directory) / "report")
            self.assertTrue(paths[0].exists())

    @unittest.skipUnless(importlib.util.find_spec("openpyxl"), "openpyxl ausente")
    def test_excel_escapes_formula_injection(self) -> None:
        from openpyxl import load_workbook
        with tempfile.TemporaryDirectory() as directory:
            rows = {"inventario": [{"hostname": "+SUM(1,1)"}]}
            path = export_excel(rows, Path(directory) / "report")[0]
            workbook = load_workbook(path, data_only=False)
            self.assertEqual(workbook["inventario"]["A2"].value, "'+SUM(1,1)")

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "reportlab ausente")
    def test_pdf_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = export_pdf(self.rows, Path(directory) / "report")
            self.assertTrue(paths[0].exists())
            self.assertGreater(paths[0].stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
