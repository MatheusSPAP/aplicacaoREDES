"""Mapeia dispositivos ativos na rede local usando requisições ARP.

O programa deve ser executado com privilégios de administrador/root, pois o
Scapy precisa abrir um socket de camada 2 para enviar quadros Ethernet.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import math
import os
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from typing import Any, Callable, Iterable, Iterator

import config
from analytics import (
    CHANGE_EVENT_TYPES,
    QueryFilters,
    fetch_availability,
    fetch_events,
    fetch_inventory,
    fetch_top_disconnects,
    parse_datetime,
)
from advanced_discovery import (
    DeviceDiscovery,
    PORT_PROFILES,
    discover_devices,
    parse_ports,
    scan_tcp_ports,
)
from mysql_storage import (
    DeviceEvent,
    InventoryEvent,
    ResilientMySQL,
    acquire_scan_lock,
    get_device_history,
    get_online_device_count,
    new_scan_key,
    normalize_mac,
    release_scan_lock,
    save_inventory,
    save_scan,
)
from reporting import generate_report, next_scheduled_time

try:
    from scapy.all import ARP, Ether, conf, get_if_addr, srp
    from scapy.error import Scapy_Exception
except ImportError:  # Permite exibir uma mensagem melhor que um traceback.
    print(
        "Erro: a biblioteca 'scapy' não está instalada.\n"
        "Instale-a com: python -m pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1)


@dataclass(frozen=True)
class Device:
    """Representa um dispositivo que respondeu ao ARP Ping."""

    ip: str
    mac: str
    vendor: str


@dataclass(frozen=True)
class ScanTarget:
    interface: Any
    network: ipaddress.IPv4Network


@dataclass(frozen=True)
class ScanResult:
    devices: tuple[Device, ...]
    healthy: bool
    error: str | None
    started_at: datetime
    duration_seconds: float


@dataclass(frozen=True)
class PendingScan:
    key: str
    target: ScanTarget
    result: ScanResult
    discoveries: tuple[DeviceDiscovery, ...] = ()


def route_value_to_int(value: Any) -> int:
    """Converte campos de rota do Scapy, que variam entre int e texto."""

    return int(ipaddress.IPv4Address(value)) if isinstance(value, str) else int(value)


def network_from_route(interface: Any, ip: str) -> ipaddress.IPv4Network:
    """Obtém a sub-rede associada a uma interface/IP na tabela do Scapy."""

    ip_as_int = int(ipaddress.IPv4Address(ip))
    candidates: list[int] = []
    for route_network, route_mask, gateway, route_iface, output_ip, _metric in conf.route.routes:
        try:
            network_as_int = route_value_to_int(route_network)
            mask_as_int = route_value_to_int(route_mask)
        except (TypeError, ValueError):
            continue

        same_interface = route_iface == interface or str(route_iface) == str(interface)
        same_source_ip = str(output_ip) == str(ip)
        directly_connected = gateway == 0 or str(gateway) in {"0", "0.0.0.0"}
        contains_ip = (ip_as_int & mask_as_int) == network_as_int
        if (
            (same_interface or same_source_ip)
            and directly_connected
            and mask_as_int
            and contains_ip
        ):
            candidates.append(mask_as_int)

    if not candidates:
        raise RuntimeError(
            "não foi possível obter a máscara da interface na tabela de rotas "
            f"do Scapy (interface={interface!s}, IPv4={ip})"
        )

    # Uma rota /32 normalmente representa apenas o host, não o segmento LAN.
    subnet_candidates = [mask for mask in candidates if mask != 0xFFFFFFFF]
    selected_mask = max(subnet_candidates or candidates, key=int.bit_count)
    return ipaddress.IPv4Network(
        f"{ip}/{ipaddress.IPv4Address(selected_mask)}", strict=False
    )


def discover_main_network() -> tuple[Any, ipaddress.IPv4Network]:
    """Retorna a interface da rota padrão e sua sub-rede IPv4.

    Consultar a rota para um IPv4 público faz o Scapy escolher a interface que
    o sistema operacional usaria para tráfego IPv4 comum. Essa consulta apenas
    lê a tabela de rotas; nenhum pacote é enviado ao endereço.
    """

    interface, route_ip, _gateway = conf.route.route("1.1.1.1")
    ip = route_ip or get_if_addr(interface)

    if not ip or ip == "0.0.0.0":
        raise RuntimeError("não foi possível obter o IPv4 da interface principal")

    local_ip = ipaddress.IPv4Address(ip)
    if local_ip.is_link_local:
        # Certos backends do Npcap selecionam primeiro um adaptador APIPA. Nesse
        # caso, procura explicitamente a rota padrão válida de menor métrica.
        default_routes: list[tuple[int, Any, str]] = []
        for route_network, route_mask, _gw, route_iface, output_ip, metric in conf.route.routes:
            try:
                candidate_ip = ipaddress.IPv4Address(str(output_ip))
                is_default = route_value_to_int(route_network) == 0 and route_value_to_int(route_mask) == 0
                usable_ip = not (
                    candidate_ip.is_unspecified
                    or candidate_ip.is_loopback
                    or candidate_ip.is_link_local
                )
                if is_default and usable_ip:
                    default_routes.append((int(metric), route_iface, str(candidate_ip)))
            except (ipaddress.AddressValueError, TypeError, ValueError):
                continue

        if default_routes:
            _metric, interface, ip = min(default_routes, key=lambda route: route[0])
            local_ip = ipaddress.IPv4Address(ip)
        else:
            raise RuntimeError(
                f"a interface selecionada possui apenas o endereço link-local {ip} "
                "(APIPA). Conecte o computador ao Wi-Fi/Ethernet e confirme se ele "
                "recebeu um IPv4 válido via DHCP"
            )

    try:
        network = network_from_route(interface, ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise RuntimeError(f"configuração IPv4 inválida para {ip}") from exc

    return interface, network


def resolve_scan_target(
    interface_name: str | None, network_cidr: str | None
) -> tuple[Any, ipaddress.IPv4Network]:
    """Combina opções manuais com a descoberta automática da rede local."""

    network: ipaddress.IPv4Network | None = None
    if network_cidr:
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
            raise ValueError(
                f"rede inválida: {network_cidr!r}; use o formato 192.168.1.0/24"
            ) from exc

    if interface_name:
        interface: Any = interface_name
        if network is None:
            interface_ip = get_if_addr(interface)
            if not interface_ip or interface_ip == "0.0.0.0":
                raise RuntimeError(
                    f"a interface {interface_name!r} não possui um endereço IPv4"
                )
            network = network_from_route(interface, interface_ip)
        return interface, network

    if network is not None:
        # Escolhe a interface cuja rota alcança a rede informada.
        probe_ip = str(next(network.hosts(), network.network_address))
        interface, _source_ip, _gateway = conf.route.route(probe_ip)
        return interface, network

    return discover_main_network()


def validate_local_target(interface: Any, network: ipaddress.IPv4Network) -> None:
    """Impede ARP em redes que não pertencem ao segmento local da interface."""

    interface_ip = get_if_addr(interface)
    if not interface_ip or interface_ip == "0.0.0.0":
        raise RuntimeError(f"a interface {interface!s} não possui IPv4 ativo")
    try:
        connected_network = network_from_route(interface, interface_ip)
    except RuntimeError:
        # Quando o Npcap não expõe a máscara, uma rede manual ainda é válida se
        # contiver o endereço da própria interface.
        if ipaddress.IPv4Address(interface_ip) in network:
            return
        raise
    if not network.subnet_of(connected_network):
        raise ValueError(
            f"a rede {network.with_prefixlen} não está no segmento local "
            f"{connected_network.with_prefixlen} da interface {interface!s}; "
            "ARP não atravessa roteadores"
        )


def resolve_targets(args: argparse.Namespace) -> list[ScanTarget]:
    """Resolve o alvo legado ou a lista repetível --alvo REDE@INTERFACE."""

    raw_targets = args.alvo or []
    targets: list[ScanTarget] = []
    if raw_targets:
        for raw in raw_targets:
            if "@" in raw:
                network_text, interface_text = raw.rsplit("@", 1)
                if not interface_text:
                    raise ValueError(f"alvo inválido: {raw!r}")
            else:
                network_text, interface_text = raw, None
            interface, network = resolve_scan_target(interface_text, network_text)
            validate_local_target(interface, network)
            targets.append(ScanTarget(interface, network))
    else:
        interface, network = resolve_scan_target(args.interface, args.rede)
        validate_local_target(interface, network)
        targets.append(ScanTarget(interface, network))

    seen: set[str] = set()
    for target in targets:
        key = target.network.with_prefixlen
        if key in seen:
            raise ValueError(f"a rede {key} foi informada mais de uma vez")
        seen.add(key)
    return targets


def batched(values: Iterable[ipaddress.IPv4Address], size: int) -> Iterator[list[str]]:
    """Divide os endereços em lotes para não criar todos os pacotes de uma vez."""

    batch: list[str] = []
    for value in values:
        batch.append(str(value))
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def lookup_vendor(mac: str) -> str:
    """Consulta o fabricante na base OUI (manuf) distribuída com o Scapy."""

    try:
        result = conf.manufdb.lookup(mac)
        # Em versões recentes, lookup retorna (nome curto, nome completo).
        if isinstance(result, tuple):
            short_name, long_name = result
            return long_name or short_name or "Desconhecido"
        if result:
            return str(result)
    except (AttributeError, KeyError, TypeError):
        pass
    return "Desconhecido"


def arp_scan(
    interface: Any,
    network: ipaddress.IPv4Network,
    timeout: float,
    retry: int,
) -> list[Device]:
    """Envia quadros Ethernet broadcast com ARP request para cada IP da rede."""

    found: dict[str, Device] = {}
    for targets in batched(network.hosts(), size=256):
        # ff:ff:ff:ff:ff:ff entrega o ARP request a todos no segmento local.
        packets = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
        answered, _unanswered = srp(
            packets,
            iface=interface,
            timeout=timeout,
            retry=retry,
            verbose=False,
        )
        for _sent, received in answered:
            ip = str(received.psrc)
            mac = str(received.hwsrc).upper()
            found[ip] = Device(ip=ip, mac=mac, vendor=lookup_vendor(mac))

    return sorted(found.values(), key=lambda device: ipaddress.ip_address(device.ip))


def perform_scan(
    interface: Any,
    network: ipaddress.IPv4Network,
    timeout: float,
    retry: int,
    *,
    scan_function: Callable[[Any, ipaddress.IPv4Network, float, int], list[Device]] = arp_scan,
) -> ScanResult:
    """Executa ARP e informa separadamente resultado vazio e falha de saúde."""

    started_at = datetime.now()
    started = time.monotonic()
    try:
        validate_local_target(interface, network)
        devices = scan_function(interface, network, timeout, retry)
        # Uma rodada sem qualquer resposta não fornece evidência suficiente para
        # incrementar ausências: interface, Npcap ou enlace podem ter falhado.
        if not devices:
            return ScanResult(
                (),
                False,
                "nenhuma resposta ARP; contadores de ausência preservados",
                started_at,
                time.monotonic() - started,
            )
        return ScanResult(
            tuple(devices), True, None, started_at, time.monotonic() - started
        )
    except (PermissionError, OSError, RuntimeError, Scapy_Exception) as exc:
        return ScanResult(
            (), False, str(exc), started_at, time.monotonic() - started
        )


def protect_against_mass_disappearance(
    result: ScanResult,
    expected_online: int,
    *,
    minimum_ratio: float = 0.25,
) -> ScanResult:
    """Marca quedas anormais de respostas como falha geral, não ausências."""

    if not result.healthy or expected_online < 4:
        return result
    minimum_responses = math.ceil(expected_online * minimum_ratio)
    if len(result.devices) >= minimum_responses:
        return result
    return ScanResult(
        result.devices,
        False,
        (
            f"queda anormal de respostas ARP: {len(result.devices)} de "
            f"{expected_online} dispositivos anteriormente online; presença preservada"
        ),
        result.started_at,
        result.duration_seconds,
    )


def enrich_devices(
    devices: Iterable[Device], args: argparse.Namespace, logger: logging.Logger
) -> tuple[DeviceDiscovery, ...]:
    """Executa recursos opcionais sem propagar falhas para o scanner ARP."""

    if not args.resolver_hostname and not args.scan_portas:
        return ()
    try:
        ports = parse_ports(args.portas, args.perfil_portas)
        return discover_devices(
            devices,
            resolve_names=args.resolver_hostname,
            scan_ports=args.scan_portas,
            ports=ports,
            timeout=args.port_timeout,
            max_workers=args.max_conexoes,
        )
    except Exception as exc:
        logger.exception("Falha no enriquecimento opcional: %s", exc)
        print(f"Aviso: descoberta avançada falhou: {exc}", file=sys.stderr)
        return ()


def print_table(
    devices: list[Device], discoveries: Iterable[DeviceDiscovery] = ()
) -> None:
    """Imprime uma tabela alinhada, sem exigir bibliotecas adicionais."""

    by_ip = {item.ip: item for item in discoveries}
    headers = ("Endereço IP", "MAC Address", "Hostname", "Vendor/Fabricante")
    rows = [
        (
            device.ip,
            device.mac,
            by_ip.get(device.ip).hostname if by_ip.get(device.ip) else "-",
            device.vendor,
        )
        for device in devices
    ]
    rows = [tuple(value or "-" for value in row) for row in rows]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        if rows
        else len(headers[index])
        for index in range(4)
    ]

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    print(separator)
    print("| " + " | ".join(headers[i].ljust(widths[i]) for i in range(4)) + " |")
    print(separator)
    for row in rows:
        print("| " + " | ".join(row[i].ljust(widths[i]) for i in range(4)) + " |")
    print(separator)


def print_port_results(discoveries: Iterable[DeviceDiscovery]) -> None:
    for item in discoveries:
        if not item.ports:
            continue
        print(f"\nPortas de {item.ip} ({item.hostname or item.mac or 'sem identificação'}):")
        for result in item.ports:
            service = result.service or "desconhecido"
            confidence = f", {result.confidence}" if result.confidence else ""
            print(f"  TCP/{result.port:<5} {result.state:<11} {service}{confidence}")


def print_inventory_events(events: Iterable[InventoryEvent]) -> None:
    labels = {
        "HOSTNAME_DISCOVERED": "HOSTNAME DESCOBERTO",
        "HOSTNAME_CHANGED": "HOSTNAME ALTERADO",
        "PORT_OPENED": "PORTA ABERTA",
        "PORT_CLOSED": "PORTA FECHADA",
        "SERVICE_CHANGED": "SERVIÇO ALTERADO",
    }
    for event in events:
        subject = f" TCP/{event.port}" if event.port is not None else ""
        change = f" {event.old_value or '-'} -> {event.new_value or '-'}"
        print(
            f"[{event.occurred_at:%d/%m/%Y %H:%M:%S}] "
            f"{labels.get(event.event_type, event.event_type)}: "
            f"MAC={event.mac} REDE={event.network}{subject}{change}"
        )


def mysql_config_from_args(args: argparse.Namespace) -> dict[str, Any]:
    """Monta a configuração do banco sem expor a senha no terminal."""

    password = os.getenv("NETWORK_MAPPER_DB_PASSWORD", config.MYSQL_PASSWORD)
    if password == "COLOQUE_SUA_SENHA_AQUI":
        raise ValueError("edite MYSQL_PASSWORD no arquivo config.py")
    return {
        "host": args.mysql_host,
        "port": args.mysql_port,
        "user": args.mysql_user,
        "password": password,
        "database": args.mysql_database,
        "connection_timeout": 10,
    }


def resilient_database_from_args(
    args: argparse.Namespace, logger: logging.Logger
) -> ResilientMySQL:
    return ResilientMySQL(
        mysql_config_from_args(args),
        max_attempts=args.mysql_retries,
        base_delay=args.mysql_retry_delay,
        logger=logger,
    )


def print_events(events: Iterable[DeviceEvent]) -> None:
    """Exibe alertas produzidos pela atualização de presença."""

    labels = {
        "NEW": "NOVO",
        "OFFLINE": "OFFLINE",
        "RECONNECTED": "RECONECTADO",
        "IP_CHANGED": "IP ALTERADO",
    }
    for event in events:
        timestamp = event.occurred_at.strftime("%d/%m/%Y %H:%M:%S")
        ip_text = event.ip or "sem IP"
        if event.event_type == "IP_CHANGED":
            ip_text = f"{event.previous_ip or 'sem IP'} -> {ip_text}"
        network_text = f" REDE={event.network}" if event.network else ""
        print(
            f"[{timestamp}] ALERTA {labels.get(event.event_type, event.event_type)}: "
            f"IP={ip_text} MAC={event.mac}{network_text}"
        )


def print_device_history(history: Any) -> None:
    """Formata no terminal o estado, IPs e eventos de um dispositivo."""

    print(f"MAC: {history.mac}")
    print(f"Fabricante: {history.vendor}")
    print(f"Primeira detecção: {history.first_seen:%d/%m/%Y %H:%M:%S}")
    print(f"Última detecção: {history.last_seen:%d/%m/%Y %H:%M:%S}")

    print("\nEstado por rede:")
    for state in history.networks:
        print(
            f"  {state.network} | {state.status.upper()} | IP={state.current_ip or '-'} "
            f"| ausências={state.missing_checks}/3 | última={state.last_seen:%d/%m/%Y %H:%M:%S}"
        )

    print("\nIPs utilizados:")
    for network, ip, first_seen, last_seen, sightings in history.ips:
        print(
            f"  {network} | {ip} | primeira: {first_seen:%d/%m/%Y %H:%M:%S} | "
            f"última: {last_seen:%d/%m/%Y %H:%M:%S} | detecções: {sightings}"
        )

    print("\nEventos:")
    if history.events:
        print_events(history.events)
    else:
        print("  Nenhum evento registrado.")

    print("\nHostnames conhecidos:")
    if history.hostnames:
        for network, hostname, source, first_seen, last_seen, sightings in history.hostnames:
            print(
                f"  {network} | {hostname} ({source or 'fonte desconhecida'}) | "
                f"primeira={first_seen:%d/%m/%Y %H:%M:%S} | "
                f"última={last_seen:%d/%m/%Y %H:%M:%S} | detecções={sightings}"
            )
    else:
        print("  Nenhum hostname registrado.")

    print("\nPortas e serviços atuais:")
    if history.ports:
        for network, port, state, last_result, service, confidence, checked in history.ports:
            print(
                f"  {network} | TCP/{port} {state} (último={last_result}) | "
                f"{service or 'desconhecido'} [{confidence or 'sem confirmação'}] | "
                f"{checked:%d/%m/%Y %H:%M:%S}"
            )
    else:
        print("  Nenhuma porta registrada.")

    print("\nEventos de inventário:")
    if history.inventory_events:
        for network, event_type, port, old_value, new_value, occurred_at in history.inventory_events:
            subject = f"TCP/{port}" if port is not None else "hostname"
            print(
                f"  [{occurred_at:%d/%m/%Y %H:%M:%S}] {network} | "
                f"{event_type} {subject}: {old_value or '-'} -> {new_value or '-'}"
            )
    else:
        print("  Nenhum evento de inventário registrado.")


def configure_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("network_mapper")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    return logger


def _persist_pending(
    database: ResilientMySQL,
    pending: deque[PendingScan],
    logger: logging.Logger,
) -> None:
    """Persiste em ordem; mantém na fila se o MySQL continuar indisponível."""

    while pending:
        item = pending[0]
        try:
            diff, inventory_events = database.run(
                lambda connection: persist_scan_bundle(
                    connection,
                    item,
                )
            )
        except Exception as exc:
            logger.exception("Falha ao persistir scan %s: %s", item.key, exc)
            print(f"MySQL indisponível; scan mantido na fila: {exc}", file=sys.stderr)
            return
        pending.popleft()
        if item.result.healthy:
            print(
                f"{len(item.result.devices)} ativo(s); snapshot MySQL #{diff.scan_id}; "
                f"{len(diff.events)} alteração(ões)."
            )
            print_events(diff.events)
            print_inventory_events(inventory_events)
        else:
            print(
                f"Scan sem saúde salvo como #{diff.scan_id}; presença não alterada: "
                f"{item.result.error}",
                file=sys.stderr,
            )


def persist_scan_bundle(
    connection: Any, item: PendingScan
) -> tuple[Any, tuple[InventoryEvent, ...]]:
    """Persiste presença e inventário; retries reutilizam o mesmo scan UUID."""

    diff = save_scan(
        connection,
        str(item.target.interface),
        item.target.network.with_prefixlen,
        item.result.devices,
        healthy=item.result.healthy,
        error_message=item.result.error,
        duration_seconds=item.result.duration_seconds,
        scan_key=item.key,
        observed_at=item.result.started_at,
    )
    inventory_events: tuple[InventoryEvent, ...] = ()
    if item.result.healthy and item.discoveries:
        inventory_events = save_inventory(
            connection,
            diff.scan_id,
            item.target.network.with_prefixlen,
            item.discoveries,
            observed_at=item.result.started_at,
        )
    return diff, inventory_events


def next_scan_deadline(started_monotonic: float, interval: float) -> float:
    """Agenda pelo início: a duração do scan é descontada do intervalo."""

    return started_monotonic + interval


def monitor_network(
    database: ResilientMySQL,
    targets: list[ScanTarget],
    args: argparse.Namespace,
    logger: logging.Logger,
) -> None:
    """Agenda alvos sequencialmente, sem sobreposição, até Ctrl+C."""

    print(
        f"Monitoramento de {len(targets)} rede(s) a cada {args.intervalo:g}s. "
        "Pressione Ctrl+C para interromper."
    )
    next_run = {target.network.with_prefixlen: time.monotonic() for target in targets}
    cycles = {target.network.with_prefixlen: 0 for target in targets}
    pending: deque[PendingScan] = deque()
    while True:
        target = min(targets, key=lambda item: next_run[item.network.with_prefixlen])
        network_key = target.network.with_prefixlen
        delay = next_run[network_key] - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        cycle_started = time.monotonic()
        cycles[network_key] += 1
        next_run[network_key] = next_scan_deadline(cycle_started, args.intervalo)
        print(
            f"\n[{datetime.now():%d/%m/%Y %H:%M:%S}] "
            f"Varredura de {network_key} iniciada..."
        )
        try:
            acquired, expected_online = database.run(
                lambda connection: (
                    acquire_scan_lock(connection, network_key),
                    get_online_device_count(connection, network_key),
                )
            )
        except Exception as exc:
            logger.exception("Não foi possível obter lock para %s: %s", network_key, exc)
            print(f"MySQL indisponível; ciclo de {network_key} adiado.", file=sys.stderr)
            continue
        if not acquired:
            logger.warning("Scan concorrente ignorado para %s", network_key)
            print(f"Outra instância já monitora {network_key}; ciclo ignorado.")
            continue
        try:
            result = perform_scan(
                target.interface, target.network, args.timeout, args.retry
            )
            result = protect_against_mass_disappearance(result, expected_online)
            if not result.healthy:
                logger.error("Falha de scan em %s: %s", network_key, result.error)
            else:
                logger.info(
                    "Scan saudável em %s: %d dispositivos em %.2fs",
                    network_key, len(result.devices), result.duration_seconds,
                )
            run_inventory = (
                result.healthy
                and (args.resolver_hostname or args.scan_portas)
                and (cycles[network_key] - 1) % args.inventario_cada == 0
            )
            discoveries = (
                enrich_devices(result.devices, args, logger) if run_inventory else ()
            )
            if discoveries:
                print_table(list(result.devices), discoveries)
                print_port_results(discoveries)
            pending.append(PendingScan(new_scan_key(), target, result, discoveries))
            _persist_pending(database, pending, logger)
        finally:
            try:
                database.run(
                    lambda connection: release_scan_lock(connection, network_key)
                )
            except Exception as exc:
                logger.warning("Falha ao liberar lock de %s: %s", network_key, exc)


def filters_from_args(args: argparse.Namespace) -> QueryFilters:
    network = (
        ipaddress.IPv4Network(args.rede, strict=False).with_prefixlen
        if args.rede
        else None
    )
    filter_ip = str(ipaddress.IPv4Address(args.filtro_ip)) if args.filtro_ip else None
    filter_mac = normalize_mac(args.filtro_mac) if args.filtro_mac else None
    page_size = args.por_pagina or args.limite
    if args.pagina < 1 or page_size < 1:
        raise ValueError("--pagina e --por-pagina/--limite devem ser maiores que zero")
    return QueryFilters(
        network=network,
        mac=filter_mac,
        ip=filter_ip,
        status=args.status,
        start=parse_datetime(args.data_inicio),
        end=parse_datetime(args.data_fim, end_of_day=True),
        limit=page_size,
        offset=(args.pagina - 1) * page_size,
    )


def print_rows(rows: list[dict[str, Any]]) -> None:
    if not rows:
        print("Nenhum registro encontrado.")
        return
    fields = list(rows[0])
    rendered = [
        [
            value.strftime("%d/%m/%Y %H:%M:%S")
            if isinstance(value, datetime)
            else ("-" if value is None else str(value))
            for value in (row.get(field) for field in fields)
        ]
        for row in rows
    ]
    widths = [
        min(40, max(len(field), *(len(row[index]) for row in rendered)))
        for index, field in enumerate(fields)
    ]
    print(" | ".join(field[: widths[i]].ljust(widths[i]) for i, field in enumerate(fields)))
    print("-+-".join("-" * width for width in widths))
    for row in rendered:
        print(" | ".join(value[: widths[i]].ljust(widths[i]) for i, value in enumerate(row)))
    print(f"\n{len(rows)} registro(s).")


def run_advanced_query(connection: Any, query_type: str, filters: QueryFilters) -> list[dict[str, Any]]:
    if query_type == "inventario":
        return fetch_inventory(connection, filters)
    if query_type == "eventos":
        return fetch_events(connection, filters)
    if query_type == "desconexoes":
        return fetch_top_disconnects(connection, filters)
    if query_type == "disponibilidade":
        return fetch_availability(connection, filters)
    if query_type == "alteracoes":
        return fetch_events(connection, filters, event_types=CHANGE_EVENT_TYPES)
    raise ValueError(f"consulta desconhecida: {query_type}")


def scheduled_period(base: QueryFilters, frequency: str, due_at: datetime) -> QueryFilters:
    if base.start or base.end:
        return base
    if frequency == "diario":
        start = due_at - timedelta(days=1)
    elif frequency == "semanal":
        start = due_at - timedelta(days=7)
    else:
        previous_month = due_at.month - 1 or 12
        previous_year = due_at.year - 1 if due_at.month == 1 else due_at.year
        start = due_at.replace(year=previous_year, month=previous_month, day=1)
    return QueryFilters(
        network=base.network, mac=base.mac, ip=base.ip, status=base.status,
        start=start, end=due_at - timedelta(microseconds=1), limit=base.limit,
        offset=base.offset,
    )


def schedule_reports(
    database: ResilientMySQL,
    frequency: str,
    report_type: str,
    output_format: str,
    filters: QueryFilters,
    output_dir: str,
    generate_now: bool,
    logger: logging.Logger,
) -> None:
    print(f"Agendador {frequency} iniciado. Pressione Ctrl+C para interromper.")
    if generate_now:
        paths = database.run(
            lambda connection: generate_report(
                connection, report_type, output_format, filters, output_dir
            )
        )
        for path in paths:
            print(f"Relatório gerado: {path.resolve()}")
    while True:
        due_at = next_scheduled_time(datetime.now(), frequency)
        print(f"Próxima geração: {due_at:%d/%m/%Y %H:%M:%S}")
        time.sleep(max(0.0, (due_at - datetime.now()).total_seconds()))
        period = scheduled_period(filters, frequency, due_at)
        try:
            paths = database.run(
                lambda connection: generate_report(
                    connection,
                    report_type,
                    output_format,
                    period,
                    output_dir,
                    generated_at=due_at,
                )
            )
            for path in paths:
                print(f"Relatório gerado: {path.resolve()}")
            logger.info("Relatório programado %s gerado", report_type)
        except Exception as exc:
            logger.exception("Falha no relatório programado: %s", exc)
            print(f"Falha ao gerar relatório: {exc}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mapeia a rede local por ARP Ping.")
    parser.add_argument(
        "--rede",
        metavar="CIDR",
        help="sub-rede a examinar, por exemplo 192.168.1.0/24",
    )
    parser.add_argument(
        "--interface",
        metavar="NOME",
        help="interface do Scapy/Npcap a utilizar (padrão: automática)",
    )
    parser.add_argument(
        "--alvo",
        action="append",
        metavar="REDE[@INTERFACE]",
        help="alvo repetível para múltiplas redes, exemplo 192.168.1.0/24@Wi-Fi",
    )
    parser.add_argument(
        "--salvar-mysql",
        action="store_true",
        help="salva a varredura e o histórico no MySQL",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--monitorar",
        action="store_true",
        help="repete varreduras e salva alterações até Ctrl+C",
    )
    modes.add_argument(
        "--historico",
        metavar="MAC",
        help="consulta no MySQL o histórico de um endereço MAC",
    )
    modes.add_argument(
        "--consultar",
        choices=("inventario", "eventos", "alteracoes", "desconexoes", "disponibilidade"),
        help="executa uma consulta histórica avançada",
    )
    modes.add_argument(
        "--relatorio",
        choices=("inventario", "eventos", "alteracoes", "desconexoes", "disponibilidade", "completo"),
        help="gera um relatório imediatamente",
    )
    modes.add_argument(
        "--agendar-relatorios",
        choices=("diario", "semanal", "mensal"),
        help="mantém um agendador automático de relatórios",
    )
    parser.add_argument(
        "--intervalo",
        type=float,
        default=60.0,
        help="segundos entre varreduras no monitoramento (padrão: 60)",
    )
    parser.add_argument(
        "--log-file",
        default="network_mapper.log",
        help="arquivo rotativo de execução e erros (padrão: network_mapper.log)",
    )
    parser.add_argument(
        "--resolver-hostname",
        action="store_true",
        help="resolve hostnames por DNS reverso/FQDN",
    )
    parser.add_argument(
        "--scan-portas",
        action="store_true",
        help="verifica portas TCP e identifica serviços nos dispositivos",
    )
    parser.add_argument(
        "--portas",
        metavar="LISTA",
        help="portas específicas, exemplo 22,80,443,8000-8005",
    )
    parser.add_argument(
        "--perfil-portas",
        choices=sorted(PORT_PROFILES),
        default=getattr(config, "PORT_SCAN_DEFAULT_PROFILE", "common"),
        help="conjunto de portas usado quando --portas não for informado",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=getattr(config, "PORT_SCAN_TIMEOUT", 0.5),
        help="timeout de cada conexão TCP em segundos (padrão: 0.5)",
    )
    parser.add_argument(
        "--max-conexoes",
        type=int,
        default=getattr(config, "PORT_SCAN_MAX_CONNECTIONS", 32),
        help="limite global de sockets simultâneos (padrão: 32)",
    )
    parser.add_argument(
        "--inventario-cada",
        type=int,
        default=getattr(config, "INVENTORY_EVERY_N_SCANS", 5),
        help="enriquece a cada N scans no monitoramento (padrão: 5)",
    )
    parser.add_argument(
        "--host",
        action="append",
        metavar="IP",
        help="IP repetível para executar somente o scanner TCP",
    )
    parser.add_argument("--filtro-ip", metavar="IP", help="filtra consultas/relatórios por IP")
    parser.add_argument("--filtro-mac", metavar="MAC", help="filtra consultas/relatórios por MAC")
    parser.add_argument(
        "--status", choices=("online", "offline"), help="filtra pelo status atual"
    )
    parser.add_argument(
        "--data-inicio", metavar="DATA", help="início: AAAA-MM-DD ou AAAA-MM-DD HH:MM:SS"
    )
    parser.add_argument(
        "--data-fim", metavar="DATA", help="fim: AAAA-MM-DD ou AAAA-MM-DD HH:MM:SS"
    )
    parser.add_argument(
        "--limite", type=int, default=1000, help="máximo de registros por consulta (padrão: 1000)"
    )
    parser.add_argument(
        "--pagina", type=int, default=1, help="página da consulta histórica (padrão: 1)"
    )
    parser.add_argument(
        "--por-pagina", type=int, help="registros por página; substitui --limite"
    )
    parser.add_argument(
        "--formato", choices=("csv", "xlsx", "pdf"), default="pdf",
        help="formato do relatório (padrão: pdf)",
    )
    parser.add_argument(
        "--pasta-relatorios", default="relatorios", help="diretório base dos relatórios"
    )
    parser.add_argument(
        "--tipo-relatorio",
        choices=("inventario", "eventos", "alteracoes", "desconexoes", "disponibilidade", "completo"),
        default="completo",
        help="conteúdo usado pelo agendador (padrão: completo)",
    )
    parser.add_argument(
        "--gerar-agora", action="store_true", help="gera uma cópia ao iniciar o agendador"
    )
    parser.add_argument(
        "--mysql-host",
        default=os.getenv("NETWORK_MAPPER_DB_HOST", config.MYSQL_HOST),
        help="servidor MySQL (padrão: localhost)",
    )
    parser.add_argument(
        "--mysql-port",
        type=int,
        default=int(os.getenv("NETWORK_MAPPER_DB_PORT", str(config.MYSQL_PORT))),
        help="porta do MySQL (padrão: 3306)",
    )
    parser.add_argument(
        "--mysql-user",
        default=os.getenv("NETWORK_MAPPER_DB_USER", config.MYSQL_USER),
        help="usuário do MySQL (padrão: root)",
    )
    parser.add_argument(
        "--mysql-database",
        default=os.getenv("NETWORK_MAPPER_DB_NAME", config.MYSQL_DATABASE),
        help="nome do banco (padrão: network_mapper)",
    )
    parser.add_argument(
        "--mysql-retries",
        type=int,
        default=getattr(config, "MYSQL_RECONNECT_ATTEMPTS", 5),
        help="tentativas por operação ao reconectar ao MySQL (padrão: 5)",
    )
    parser.add_argument(
        "--mysql-retry-delay",
        type=float,
        default=getattr(config, "MYSQL_RECONNECT_BASE_DELAY", 1.0),
        help="atraso inicial da reconexão progressiva (padrão: 1s)",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="espera por lote em segundos (padrão: 2)")
    parser.add_argument("--retry", type=int, default=0, help="tentativas extras por lote (padrão: 0)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (
        args.timeout <= 0
        or args.retry < 0
        or args.intervalo <= 0
        or args.mysql_retries <= 0
        or args.mysql_retry_delay < 0
        or args.port_timeout <= 0
        or args.max_conexoes <= 0
        or args.max_conexoes > 256
        or args.inventario_cada <= 0
        or args.limite <= 0
        or args.limite > 100000
        or args.pagina <= 0
        or (args.por_pagina is not None and not 1 <= args.por_pagina <= 100000)
    ):
        print(
            "Erro: --timeout e --intervalo devem ser positivos; "
            "--retry e --mysql-retry-delay não podem ser negativos; "
            "--mysql-retries e --pagina devem ser positivos; limites de consulta "
            "devem estar entre 1 e 100000.",
            file=sys.stderr,
        )
        return 2

    try:
        logger = configure_logging(args.log_file)
        # Valida cedo, mesmo que o perfil só seja usado mais tarde.
        parse_ports(args.portas, args.perfil_portas)
        if args.consultar:
            filters = filters_from_args(args)
            database = resilient_database_from_args(args, logger)
            try:
                rows = database.run(
                    lambda connection: run_advanced_query(
                        connection, args.consultar, filters
                    )
                )
                print_rows(rows)
                return 0
            finally:
                database.close()

        if args.relatorio:
            filters = filters_from_args(args)
            database = resilient_database_from_args(args, logger)
            try:
                paths = database.run(
                    lambda connection: generate_report(
                        connection,
                        args.relatorio,
                        args.formato,
                        filters,
                        args.pasta_relatorios,
                    )
                )
                for path in paths:
                    print(f"Relatório gerado: {path.resolve()}")
                return 0
            finally:
                database.close()

        if args.agendar_relatorios:
            filters = filters_from_args(args)
            database = resilient_database_from_args(args, logger)
            try:
                schedule_reports(
                    database,
                    args.agendar_relatorios,
                    args.tipo_relatorio,
                    args.formato,
                    filters,
                    args.pasta_relatorios,
                    args.gerar_agora,
                    logger,
                )
            finally:
                database.close()
            return 0

        if args.historico:
            database = resilient_database_from_args(args, logger)
            try:
                history_network = None
                if args.rede:
                    history_network = ipaddress.IPv4Network(
                        args.rede, strict=False
                    ).with_prefixlen
                history = database.run(
                    lambda connection: get_device_history(
                        connection, args.historico, history_network
                    )
                )
                if history is None:
                    print(f"Nenhum histórico encontrado para {args.historico}.")
                    return 1
                print_device_history(history)
                return 0
            finally:
                database.close()

        targets = resolve_targets(args)
        for target in targets:
            print(f"Interface utilizada: {target.interface}")
            print(f"Sub-rede utilizada: {target.network.with_prefixlen}")

        if args.host:
            if args.monitorar:
                raise ValueError("--host não pode ser combinado com --monitorar")
            host_ips = [str(ipaddress.IPv4Address(value)) for value in args.host]
            for host_ip in host_ips:
                if not any(ipaddress.IPv4Address(host_ip) in target.network for target in targets):
                    raise ValueError(
                        f"o host {host_ip} não pertence a nenhuma rede local autorizada"
                    )
            standalone = discover_devices(
                [Device(ip, "-", "-") for ip in host_ips],
                resolve_names=args.resolver_hostname,
                scan_ports=True,
                ports=parse_ports(args.portas, args.perfil_portas),
                timeout=args.port_timeout,
                max_workers=args.max_conexoes,
            )
            print_port_results(standalone)
            return 0

        if args.monitorar:
            database = resilient_database_from_args(args, logger)
            try:
                monitor_network(database, targets, args, logger)
            finally:
                database.close()
            return 0

        database = (
            resilient_database_from_args(args, logger)
            if args.salvar_mysql
            else None
        )
        exit_code = 0
        try:
            for target in targets:
                print(f"\nProcurando dispositivos em {target.network.with_prefixlen}...\n")
                result = perform_scan(
                    target.interface, target.network, args.timeout, args.retry
                )
                if result.healthy:
                    discoveries = enrich_devices(result.devices, args, logger)
                    print_table(list(result.devices), discoveries)
                    print_port_results(discoveries)
                    print(f"\n{len(result.devices)} dispositivo(s) ativo(s) encontrado(s).")
                else:
                    discoveries = ()
                    print(f"Falha de varredura: {result.error}", file=sys.stderr)
                    logger.error(
                        "Falha de scan em %s: %s", target.network.with_prefixlen, result.error
                    )
                    exit_code = 1
                if database is not None:
                    key = new_scan_key()
                    pending_item = PendingScan(key, target, result, discoveries)
                    diff, inventory_events = database.run(
                        lambda connection, item=pending_item: persist_scan_bundle(
                            connection, item
                        )
                    )
                    print(f"Varredura #{diff.scan_id} salva no MySQL.")
                    print_events(diff.events)
                    print_inventory_events(inventory_events)
            return exit_code
        finally:
            if database is not None:
                database.close()
    except (PermissionError, OSError, Scapy_Exception) as exc:
        print(
            "Erro de acesso à rede: execute este programa como Administrador "
            f"(Windows) ou root (Linux/macOS).\nDetalhes: {exc}",
            file=sys.stderr,
        )
        return 1
    except (RuntimeError, ValueError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado com segurança pelo usuário.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
