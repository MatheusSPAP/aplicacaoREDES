"""Testes das consultas SQL sem exigir uma instância MySQL."""

from __future__ import annotations

import unittest
from datetime import datetime

from network_mapper_core.analytics import (
    CHANGE_EVENT_TYPES,
    QueryFilters,
    fetch_events,
    fetch_inventory,
)


class FakeCursor:
    def __init__(self) -> None:
        self.sql = ""
        self.params = ()

    def execute(self, sql, params=()) -> None:
        self.sql = sql
        self.params = params

    def fetchall(self):
        return []

    def close(self) -> None:
        pass


class FakeConnection:
    def __init__(self) -> None:
        self.last_cursor = None

    def cursor(self, **_kwargs):
        self.last_cursor = FakeCursor()
        return self.last_cursor


class AnalyticsQueryTests(unittest.TestCase):
    def test_changes_are_filtered_before_limit_and_paginated(self) -> None:
        connection = FakeConnection()
        fetch_events(
            connection,
            QueryFilters(limit=25, offset=50),
            event_types=CHANGE_EVENT_TYPES,
        )
        cursor = connection.last_cursor
        self.assertIn("UNION ALL", cursor.sql)
        self.assertIn("event_type IN", cursor.sql)
        self.assertTrue(cursor.sql.endswith("LIMIT %s OFFSET %s"))
        self.assertEqual(cursor.params[-2:], (25, 50))

    def test_inventory_uses_presence_overlap_and_historical_ip(self) -> None:
        connection = FakeConnection()
        fetch_inventory(
            connection,
            QueryFilters(
                ip="192.168.1.20",
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 31, 23, 59, 59),
            ),
        )
        sql = connection.last_cursor.sql
        self.assertIn("s.last_seen>=%s", sql)
        self.assertIn("s.first_seen<=%s", sql)
        self.assertIn("network_device_ips", sql)
        self.assertIn("i.last_seen>=%s", sql)
        self.assertIn("i.first_seen<=%s", sql)


if __name__ == "__main__":
    unittest.main()
