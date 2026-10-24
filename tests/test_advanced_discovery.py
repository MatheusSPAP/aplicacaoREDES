"""Testes da descoberta avançada sem DNS ou sockets reais."""

from __future__ import annotations

import argparse
import logging
import socket
import unittest
from unittest.mock import patch

from advanced_discovery import (
    parse_ports,
    resolve_hostname,
    scan_tcp_port,
)
from mysql_storage import classify_port_change
from network_mapper import Device, enrich_devices


class FakeSocket:
    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class AdvancedDiscoveryTests(unittest.TestCase):
    def test_parse_specific_ports_and_range(self) -> None:
        self.assertEqual(parse_ports("443,22,8000-8002,22", "common"), (22, 443, 8000, 8001, 8002))

    def test_parse_rejects_excessive_range(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("1-5000", "common")

    def test_reverse_dns_hostname(self) -> None:
        result = resolve_hostname(
            "192.168.1.10",
            reverse_lookup=lambda _ip: ("printer.local.", [], []),
        )
        self.assertEqual((result.hostname, result.source), ("printer.local", "reverse_dns"))

    def test_fqdn_fallback_is_non_fatal(self) -> None:
        def missing_ptr(_ip: str) -> tuple[str, list[str], list[str]]:
            raise socket.herror("sem PTR")

        result = resolve_hostname(
            "192.168.1.20",
            reverse_lookup=missing_ptr,
            fqdn_lookup=lambda _ip: "camera.local",
        )
        self.assertEqual((result.hostname, result.source), ("camera.local", "fqdn"))

    @patch("advanced_discovery._confirm_service", return_value=("SSH", "SSH-2.0-test"))
    def test_open_port_with_confirmed_service(self, _confirm: object) -> None:
        result = scan_tcp_port(
            "192.168.1.10", 22, 0.2,
            connection_factory=lambda *_args, **_kwargs: FakeSocket(),
        )
        self.assertEqual((result.state, result.service, result.confidence), ("open", "SSH", "confirmed"))

    def test_closed_and_no_response_ports(self) -> None:
        def refused(*_args: object, **_kwargs: object) -> FakeSocket:
            raise ConnectionRefusedError

        def timeout(*_args: object, **_kwargs: object) -> FakeSocket:
            raise socket.timeout

        self.assertEqual(scan_tcp_port("192.168.1.10", 445, 0.2, connection_factory=refused).state, "closed")
        self.assertEqual(scan_tcp_port("192.168.1.10", 3389, 0.2, connection_factory=timeout).state, "no_response")

    def test_no_response_preserves_previous_open_state(self) -> None:
        self.assertEqual(
            classify_port_change("open", "HTTP", "no_response", "HTTP"),
            ("open", None, None, None),
        )
        self.assertEqual(
            classify_port_change("open", "HTTP", "closed", "HTTP"),
            ("closed", "PORT_CLOSED", "HTTP", "closed"),
        )

    @patch("network_mapper.discover_devices", side_effect=OSError("falha DNS simulada"))
    def test_enrichment_failure_does_not_change_arp_devices(self, _discover: object) -> None:
        args = argparse.Namespace(
            resolver_hostname=True,
            scan_portas=False,
            portas=None,
            perfil_portas="common",
            port_timeout=0.5,
            max_conexoes=4,
        )
        devices = [Device("192.168.1.10", "AA:BB:CC:DD:EE:FF", "Vendor")]
        self.assertEqual(enrich_devices(devices, args, logging.getLogger("test")), ())
        self.assertEqual(len(devices), 1)


if __name__ == "__main__":
    unittest.main()
