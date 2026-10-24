"""Descoberta opcional de hostname, portas TCP e serviços leves."""

from __future__ import annotations

import errno
import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable


PORT_PROFILES: dict[str, tuple[int, ...]] = {
    "common": (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080),
    "web": (80, 443, 8000, 8080, 8443),
    "database": (1433, 1521, 3306, 5432, 6379, 27017),
    "remote": (22, 23, 3389, 5900),
}

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP", 8080: "HTTP", 8443: "HTTPS",
    27017: "MongoDB",
}


@dataclass(frozen=True)
class HostnameResult:
    ip: str
    hostname: str | None
    source: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class PortResult:
    ip: str
    port: int
    state: str
    service: str | None
    confidence: str | None
    evidence: str | None = None


@dataclass(frozen=True)
class DeviceDiscovery:
    ip: str
    mac: str | None
    hostname: str | None
    hostname_source: str | None
    ports: tuple[PortResult, ...]


def parse_ports(specification: str | None, profile: str) -> tuple[int, ...]:
    """Converte `22,80,8000-8002` ou um perfil em portas únicas ordenadas."""

    ports = set(PORT_PROFILES[profile])
    if specification:
        ports.clear()
        for part in specification.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                if "-" in part:
                    start_text, end_text = part.split("-", 1)
                    start, end = int(start_text), int(end_text)
                    if start > end or end - start > 1024:
                        raise ValueError
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))
            except ValueError as exc:
                raise ValueError(f"lista de portas inválida: {part!r}") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("as portas devem estar entre 1 e 65535")
    return tuple(sorted(ports))


def resolve_hostname(
    ip: str,
    *,
    reverse_lookup: Callable[[str], tuple[str, list[str], list[str]]] = socket.gethostbyaddr,
    fqdn_lookup: Callable[[str], str] = socket.getfqdn,
) -> HostnameResult:
    """Tenta PTR/reverse DNS e usa getfqdn como fallback não fatal."""

    try:
        hostname = reverse_lookup(ip)[0].rstrip(".")
        if hostname and hostname != ip:
            return HostnameResult(ip, hostname, "reverse_dns")
    except (socket.herror, socket.gaierror, OSError) as exc:
        reverse_error = str(exc)
    else:
        reverse_error = None
    try:
        hostname = fqdn_lookup(ip).rstrip(".")
        if hostname and hostname != ip:
            return HostnameResult(ip, hostname, "fqdn")
    except OSError as exc:
        return HostnameResult(ip, None, error=str(exc))
    return HostnameResult(ip, None, error=reverse_error)


def resolve_hostnames(
    ips: Iterable[str], max_workers: int = 16
) -> dict[str, HostnameResult]:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_hostname, ip): ip for ip in set(ips)}
        return {futures[future]: future.result() for future in as_completed(futures)}


def _confirm_service(sock: socket.socket, ip: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    """Faz somente banner/handshake curto; nunca autentica nem envia credenciais."""

    sock.settimeout(timeout)
    try:
        if port == 22:
            banner = sock.recv(128)
            if banner.startswith(b"SSH-"):
                return "SSH", banner.decode("ascii", "replace").strip()[:120]
        elif port == 21:
            banner = sock.recv(128)
            if banner.startswith(b"220"):
                return "FTP", banner.decode("ascii", "replace").strip()[:120]
        elif port == 3306:
            banner = sock.recv(128)
            if len(banner) > 5 and banner[4] == 10:
                return "MySQL", "handshake MySQL"
        elif port in {80, 8000, 8080}:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii"))
            banner = sock.recv(128)
            if banner.startswith(b"HTTP/"):
                return "HTTP", banner.split(b"\r\n", 1)[0].decode("ascii", "replace")[:120]
        elif port in {443, 8443}:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                return "HTTPS", f"TLS {tls_sock.version()}"
    except (OSError, ssl.SSLError, TimeoutError):
        pass
    return None, None


def scan_tcp_port(
    ip: str,
    port: int,
    timeout: float,
    *,
    connection_factory: Callable[..., socket.socket] = socket.create_connection,
) -> PortResult:
    """Testa conexão TCP e classifica serviço confirmado ou inferido."""

    try:
        with connection_factory((ip, port), timeout=timeout) as sock:
            confirmed, evidence = _confirm_service(sock, ip, port, timeout)
            inferred = KNOWN_SERVICES.get(port)
            return PortResult(
                ip, port, "open", confirmed or inferred,
                "confirmed" if confirmed else ("inferred" if inferred else None),
                evidence,
            )
    except ConnectionRefusedError:
        return PortResult(ip, port, "closed", KNOWN_SERVICES.get(port), "inferred")
    except (socket.timeout, TimeoutError):
        return PortResult(ip, port, "no_response", KNOWN_SERVICES.get(port), "inferred")
    except OSError as exc:
        refused_codes = {errno.ECONNREFUSED, 10061}
        state = "closed" if getattr(exc, "errno", None) in refused_codes else "no_response"
        return PortResult(ip, port, state, KNOWN_SERVICES.get(port), "inferred")


def scan_tcp_ports(
    ips: Iterable[str],
    ports: Iterable[int],
    *,
    timeout: float = 0.5,
    max_workers: int = 32,
) -> dict[str, tuple[PortResult, ...]]:
    """Executa no máximo `max_workers` sockets simultâneos para todos os alvos."""

    unique_ips = tuple(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in ips))
    unique_ports = tuple(sorted(set(ports)))
    results: dict[str, list[PortResult]] = {ip: [] for ip in unique_ips}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_tcp_port, ip, port, timeout): ip
            for ip in unique_ips
            for port in unique_ports
        }
        for future in as_completed(futures):
            result = future.result()
            results[result.ip].append(result)
    return {
        ip: tuple(sorted(items, key=lambda item: item.port))
        for ip, items in results.items()
    }


def discover_devices(
    devices: Iterable[object],
    *,
    resolve_names: bool,
    scan_ports: bool,
    ports: tuple[int, ...],
    timeout: float,
    max_workers: int,
) -> tuple[DeviceDiscovery, ...]:
    """Enriquece dispositivos; falhas individuais produzem campos vazios."""

    device_list = list(devices)
    ips = [str(getattr(device, "ip")) for device in device_list]
    names = resolve_hostnames(ips, max_workers) if resolve_names else {}
    port_map = (
        scan_tcp_ports(ips, ports, timeout=timeout, max_workers=max_workers)
        if scan_ports
        else {}
    )
    return tuple(
        DeviceDiscovery(
            ip=str(getattr(device, "ip")),
            mac=getattr(device, "mac", None),
            hostname=names.get(str(getattr(device, "ip")), HostnameResult("", None)).hostname,
            hostname_source=names.get(str(getattr(device, "ip")), HostnameResult("", None)).source,
            ports=port_map.get(str(getattr(device, "ip")), ()),
        )
        for device in device_list
    )
