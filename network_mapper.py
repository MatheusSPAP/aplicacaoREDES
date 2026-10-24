"""Mapeia dispositivos ativos na rede local usando requisições ARP.

O programa deve ser executado com privilégios de administrador/root, pois o
Scapy precisa abrir um socket de camada 2 para enviar quadros Ethernet.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Iterator

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


def print_table(devices: list[Device]) -> None:
    """Imprime uma tabela alinhada, sem exigir bibliotecas adicionais."""

    headers = ("Endereço IP", "MAC Address", "Vendor/Fabricante")
    rows = [(device.ip, device.mac, device.vendor) for device in devices]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        if rows
        else len(headers[index])
        for index in range(3)
    ]

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    print(separator)
    print("| " + " | ".join(headers[i].ljust(widths[i]) for i in range(3)) + " |")
    print(separator)
    for row in rows:
        print("| " + " | ".join(row[i].ljust(widths[i]) for i in range(3)) + " |")
    print(separator)


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
    parser.add_argument("--timeout", type=float, default=2.0, help="espera por lote em segundos (padrão: 2)")
    parser.add_argument("--retry", type=int, default=0, help="tentativas extras por lote (padrão: 0)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout <= 0 or args.retry < 0:
        print("Erro: --timeout deve ser positivo e --retry não pode ser negativo.", file=sys.stderr)
        return 2

    try:
        interface, network = resolve_scan_target(args.interface, args.rede)
        print(f"Interface utilizada: {interface}")
        print(f"Sub-rede utilizada: {network.with_prefixlen}")
        print("Procurando dispositivos...\n")

        devices = arp_scan(interface, network, args.timeout, args.retry)
        print_table(devices)
        print(f"\n{len(devices)} dispositivo(s) ativo(s) encontrado(s).")
        return 0
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
        print("\nVarredura interrompida pelo usuário.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
