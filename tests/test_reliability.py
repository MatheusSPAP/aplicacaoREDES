"""Testes sem tráfego ARP real e sem acesso a um servidor MySQL."""

from __future__ import annotations

import ipaddress
import unittest
from unittest.mock import patch

from mysql_storage import ResilientMySQL, advance_presence
from network_mapper import (
    Device,
    ScanResult,
    next_scan_deadline,
    perform_scan,
    protect_against_mass_disappearance,
)
from datetime import datetime


class FakeMySQLError(Exception):
    def __init__(self, message: str, errno: int = 2006) -> None:
        super().__init__(message)
        self.errno = errno


class ReliabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.network = ipaddress.IPv4Network("192.168.1.0/24")

    @patch("network_mapper.validate_local_target")
    def test_empty_arp_result_is_unhealthy(self, _validate: object) -> None:
        result = perform_scan(
            "Wi-Fi", self.network, 1.0, 0,
            scan_function=lambda *_args: [],
        )
        self.assertFalse(result.healthy)
        self.assertEqual(result.devices, ())
        self.assertIn("preservados", result.error or "")

    @patch("network_mapper.validate_local_target")
    def test_arp_exception_is_scan_failure(self, _validate: object) -> None:
        def failing_scan(*_args: object) -> list[Device]:
            raise OSError("interface indisponível")

        result = perform_scan(
            "Wi-Fi", self.network, 1.0, 0, scan_function=failing_scan
        )
        self.assertFalse(result.healthy)
        self.assertIn("interface indisponível", result.error or "")

    def test_offline_only_after_three_misses_and_not_repeated(self) -> None:
        status, misses, event = "online", 0, None
        for expected in (1, 2):
            status, misses, event = advance_presence(status, misses, seen=False)
            self.assertEqual((status, misses, event), ("online", expected, None))
        status, misses, event = advance_presence(status, misses, seen=False)
        self.assertEqual((status, misses, event), ("offline", 3, "OFFLINE"))
        self.assertEqual(
            advance_presence(status, misses, seen=False), ("offline", 3, None)
        )

    def test_reconnection_is_registered(self) -> None:
        self.assertEqual(
            advance_presence("offline", 3, seen=True),
            ("online", 0, "RECONNECTED"),
        )

    def test_network_states_are_independent(self) -> None:
        states = {
            "192.168.1.0/24": ("online", 2),
            "10.0.0.0/24": ("online", 0),
        }
        status, misses, _event = advance_presence(*states["192.168.1.0/24"], seen=False)
        states["192.168.1.0/24"] = (status, misses)
        self.assertEqual(states["192.168.1.0/24"], ("offline", 3))
        self.assertEqual(states["10.0.0.0/24"], ("online", 0))

    def test_mass_disappearance_is_treated_as_scan_failure(self) -> None:
        result = ScanResult(
            (Device("192.168.1.1", "AA:BB:CC:DD:EE:FF", "Vendor"),),
            True,
            None,
            datetime.now(),
            1.0,
        )
        protected = protect_against_mass_disappearance(result, expected_online=20)
        self.assertFalse(protected.healthy)
        self.assertIn("queda anormal", protected.error or "")

    def test_mysql_reconnects_with_progressive_retry(self) -> None:
        attempts: list[int] = []
        delays: list[float] = []
        connection = object()

        def connect_factory(_config: dict[str, object]) -> object:
            attempts.append(1)
            if len(attempts) < 3:
                raise FakeMySQLError("conexão perdida")
            return connection

        database = ResilientMySQL(
            {}, connect_factory=connect_factory, sleep=delays.append,
            max_attempts=4, base_delay=0.5,
        )
        self.assertEqual(database.run(lambda value: value), connection)
        self.assertEqual(len(attempts), 3)
        self.assertEqual(delays, [0.5, 1.0])

    def test_retry_reuses_operation_idempotency_key(self) -> None:
        keys: list[str] = []
        calls = 0

        def operation(_connection: object) -> str:
            nonlocal calls
            calls += 1
            keys.append("fixed-scan-key")
            if calls == 1:
                raise FakeMySQLError("queda após envio")
            return keys[-1]

        database = ResilientMySQL(
            {}, connect_factory=lambda _config: object(), sleep=lambda _delay: None
        )
        self.assertEqual(database.run(operation), "fixed-scan-key")
        self.assertEqual(keys, ["fixed-scan-key", "fixed-scan-key"])

    def test_scan_duration_is_subtracted_from_interval(self) -> None:
        deadline = next_scan_deadline(100.0, 60.0)
        self.assertEqual(deadline, 160.0)
        # Se o scan terminou em 115, restam 45 segundos até a próxima rodada.
        self.assertEqual(deadline - 115.0, 45.0)


if __name__ == "__main__":
    unittest.main()
