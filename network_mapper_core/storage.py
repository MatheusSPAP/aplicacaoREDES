"""Persistência transacional e resiliente do Network Mapper em MySQL."""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable, TypeVar


OFFLINE_AFTER_MISSES = 3
RETRYABLE_MYSQL_ERRORS = {2002, 2003, 2006, 2013, 2055}
T = TypeVar("T")


@dataclass(frozen=True)
class DeviceEvent:
    event_type: str
    mac: str
    ip: str | None
    occurred_at: datetime
    previous_ip: str | None = None
    network: str | None = None


@dataclass(frozen=True)
class HistoryDiff:
    scan_id: int
    new_macs: tuple[str, ...]
    removed_macs: tuple[str, ...]
    reconnected_macs: tuple[str, ...]
    events: tuple[DeviceEvent, ...]
    persisted: bool = True


@dataclass(frozen=True)
class InventoryEvent:
    event_type: str
    network: str
    mac: str
    port: int | None
    old_value: str | None
    new_value: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class NetworkState:
    network: str
    status: str
    current_ip: str | None
    first_seen: datetime
    last_seen: datetime
    missing_checks: int


@dataclass(frozen=True)
class DeviceHistory:
    mac: str
    vendor: str
    first_seen: datetime
    last_seen: datetime
    networks: tuple[NetworkState, ...]
    ips: tuple[tuple[str, str, datetime, datetime, int], ...]
    events: tuple[DeviceEvent, ...]
    hostnames: tuple[tuple[str, str, str | None, datetime, datetime, int], ...] = ()
    ports: tuple[tuple[str, int, str, str, str | None, str | None, datetime], ...] = ()
    inventory_events: tuple[tuple[str, str, int | None, str | None, str | None, datetime], ...] = ()


def _load_connector() -> Any:
    try:
        import mysql.connector
    except ImportError as exc:
        raise RuntimeError(
            "o conector MySQL não está instalado; execute "
            "'python -m pip install -r requirements.txt'"
        ) from exc
    return mysql.connector


def _validate_database_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise ValueError("o nome do banco deve conter apenas letras, números e underscore")
    return name


def normalize_mac(mac: str) -> str:
    compact = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(compact) != 12:
        raise ValueError(f"MAC inválido: {mac!r}")
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).upper()


def new_scan_key() -> str:
    """Identificador reaproveitado em retries para impedir scans duplicados."""

    return str(uuid.uuid4())


def advance_presence(
    status: str, missing_checks: int, *, seen: bool
) -> tuple[str, int, str | None]:
    """Calcula uma transição sem I/O; OFFLINE é emitido uma única vez."""

    if seen:
        return "online", 0, "RECONNECTED" if status == "offline" else None
    if status == "offline":
        return "offline", missing_checks, None
    misses = missing_checks + 1
    if misses >= OFFLINE_AFTER_MISSES:
        return "offline", misses, "OFFLINE"
    return "online", misses, None


def classify_port_change(
    previous_state: str | None,
    previous_service: str | None,
    result_state: str,
    result_service: str | None,
) -> tuple[str, str | None, str | None, str | None]:
    """Retorna estado persistido, evento e valores antigo/novo."""

    current_state = (
        previous_state
        if result_state == "no_response" and previous_state
        else result_state
    )
    if result_state == "open" and previous_state != "open":
        return current_state, "PORT_OPENED", previous_state, result_service or "open"
    if result_state == "closed" and previous_state == "open":
        return current_state, "PORT_CLOSED", previous_service or "open", "closed"
    if (
        result_state == "open"
        and previous_state == "open"
        and previous_service != result_service
    ):
        return current_state, "SERVICE_CHANGED", previous_service, result_service
    return current_state, None, None, None


def _column_exists(cursor: Any, database: str, table: str, column: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND COLUMN_NAME=%s LIMIT 1",
        (database, table, column),
    )
    return cursor.fetchone() is not None


def _index_exists(cursor: Any, database: str, table: str, index: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND INDEX_NAME=%s LIMIT 1",
        (database, table, index),
    )
    return cursor.fetchone() is not None


def _apply_safe_migrations(connection: Any, database: str) -> None:
    """Aplica apenas CREATE/ALTER aditivos e copia o estado legado."""

    cursor = connection.cursor()
    try:
        additions = (
            ("scans", "scan_key", "ALTER TABLE scans ADD COLUMN scan_key CHAR(36) NULL"),
            (
                "scans",
                "scan_status",
                "ALTER TABLE scans ADD COLUMN scan_status VARCHAR(16) NOT NULL DEFAULT 'success'",
            ),
            (
                "scans",
                "error_message",
                "ALTER TABLE scans ADD COLUMN error_message VARCHAR(1000) NULL",
            ),
            (
                "scans",
                "duration_seconds",
                "ALTER TABLE scans ADD COLUMN duration_seconds DOUBLE NULL",
            ),
            (
                "device_events",
                "network_cidr",
                "ALTER TABLE device_events ADD COLUMN network_cidr VARCHAR(43) NULL",
            ),
        )
        for table, column, statement in additions:
            if not _column_exists(cursor, database, table, column):
                cursor.execute(statement)
        if not _index_exists(cursor, database, "scans", "uq_scans_key"):
            cursor.execute("ALTER TABLE scans ADD UNIQUE INDEX uq_scans_key (scan_key)")
        if not _index_exists(cursor, database, "device_events", "idx_events_network"):
            cursor.execute(
                "ALTER TABLE device_events ADD INDEX idx_events_network "
                "(network_cidr, occurred_at)"
            )
        if not _index_exists(cursor, database, "scans", "idx_scans_health_time"):
            cursor.execute(
                "ALTER TABLE scans ADD INDEX idx_scans_health_time "
                "(network_cidr, scan_status, scanned_at)"
            )
        if not _index_exists(cursor, database, "device_hostnames", "idx_hostname_latest"):
            cursor.execute(
                "ALTER TABLE device_hostnames ADD INDEX idx_hostname_latest "
                "(network_cidr, mac_address, last_seen)"
            )
        safe_indexes = (
            ("network_device_state", "idx_state_period", "network_cidr, first_seen, last_seen, status"),
            ("network_device_ips", "idx_ip_period", "ip_address, network_cidr, first_seen, last_seen, mac_address"),
            ("device_events", "idx_events_history", "network_cidr, occurred_at, event_type, mac_address, ip_address"),
            ("inventory_events", "idx_inventory_history", "network_cidr, occurred_at, event_type, mac_address"),
        )
        for table, index, columns in safe_indexes:
            if not _index_exists(cursor, database, table, index):
                cursor.execute(f"ALTER TABLE {table} ADD INDEX {index} ({columns})")

        cursor.execute(
            "UPDATE device_events e JOIN scans s ON s.id=e.scan_id "
            "SET e.network_cidr=s.network_cidr WHERE e.network_cidr IS NULL"
        )
        cursor.execute(
            "INSERT IGNORE INTO network_device_state "
            "(network_cidr, mac_address, status, current_ip, first_seen, last_seen, missing_checks) "
            "SELECT current_network, mac_address, status, current_ip, first_seen, "
            "last_seen, missing_checks FROM devices WHERE current_network <> ''"
        )
        cursor.execute(
            "INSERT IGNORE INTO network_device_ips "
            "(network_cidr, mac_address, ip_address, first_seen, last_seen, sightings) "
            "SELECT d.current_network, i.mac_address, i.ip_address, i.first_seen, "
            "i.last_seen, i.sightings FROM device_ips i JOIN devices d "
            "ON d.mac_address=i.mac_address WHERE d.current_network <> ''"
        )
        connection.commit()
    finally:
        cursor.close()


def connect_mysql(config: dict[str, Any]) -> Any:
    """Conecta ao MySQL, preserva o esquema antigo e aplica migrações seguras."""

    connector = _load_connector()
    database = _validate_database_name(config["database"])
    server_config = {key: value for key, value in config.items() if key != "database"}
    connection = connector.connect(**server_config)
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{database}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cursor.execute(f"USE `{database}`")
        statements = (
            """CREATE TABLE IF NOT EXISTS scans (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                scanned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                interface_name VARCHAR(255) NOT NULL,
                network_cidr VARCHAR(43) NOT NULL,
                device_count INT UNSIGNED NOT NULL,
                PRIMARY KEY (id), INDEX idx_scans_network_time (network_cidr, scanned_at)
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS scan_devices (
                scan_id BIGINT UNSIGNED NOT NULL, ip_address VARCHAR(45) NOT NULL,
                mac_address CHAR(17) NOT NULL, vendor VARCHAR(255) NOT NULL,
                PRIMARY KEY (scan_id, mac_address), INDEX idx_devices_mac (mac_address),
                CONSTRAINT fk_devices_scan FOREIGN KEY (scan_id)
                    REFERENCES scans(id) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS devices (
                mac_address CHAR(17) NOT NULL, vendor VARCHAR(255) NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'online', current_ip VARCHAR(45) NULL,
                current_network VARCHAR(43) NOT NULL, first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL, missing_checks TINYINT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (mac_address), INDEX idx_devices_network_status (current_network, status)
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS device_ips (
                mac_address CHAR(17) NOT NULL, ip_address VARCHAR(45) NOT NULL,
                first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
                sightings BIGINT UNSIGNED NOT NULL DEFAULT 1,
                PRIMARY KEY (mac_address, ip_address),
                CONSTRAINT fk_ips_device FOREIGN KEY (mac_address)
                    REFERENCES devices(mac_address) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS device_events (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, mac_address CHAR(17) NOT NULL,
                scan_id BIGINT UNSIGNED NOT NULL, event_type VARCHAR(24) NOT NULL,
                ip_address VARCHAR(45) NULL, previous_ip VARCHAR(45) NULL,
                occurred_at DATETIME NOT NULL, PRIMARY KEY (id),
                INDEX idx_events_mac_time (mac_address, occurred_at),
                CONSTRAINT fk_events_device FOREIGN KEY (mac_address)
                    REFERENCES devices(mac_address) ON DELETE CASCADE,
                CONSTRAINT fk_events_scan FOREIGN KEY (scan_id)
                    REFERENCES scans(id) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS network_device_state (
                network_cidr VARCHAR(43) NOT NULL, mac_address CHAR(17) NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'online', current_ip VARCHAR(45) NULL,
                first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
                missing_checks TINYINT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (network_cidr, mac_address),
                INDEX idx_network_state_status (network_cidr, status),
                CONSTRAINT fk_network_state_device FOREIGN KEY (mac_address)
                    REFERENCES devices(mac_address) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS network_device_ips (
                network_cidr VARCHAR(43) NOT NULL, mac_address CHAR(17) NOT NULL,
                ip_address VARCHAR(45) NOT NULL, first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL, sightings BIGINT UNSIGNED NOT NULL DEFAULT 1,
                PRIMARY KEY (network_cidr, mac_address, ip_address),
                CONSTRAINT fk_network_ips_state FOREIGN KEY (network_cidr, mac_address)
                    REFERENCES network_device_state(network_cidr, mac_address) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS device_hostnames (
                network_cidr VARCHAR(43) NOT NULL, mac_address CHAR(17) NOT NULL,
                hostname VARCHAR(255) NOT NULL, source VARCHAR(32) NULL,
                first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL,
                sightings BIGINT UNSIGNED NOT NULL DEFAULT 1,
                PRIMARY KEY (network_cidr, mac_address, hostname),
                CONSTRAINT fk_hostnames_state FOREIGN KEY (network_cidr, mac_address)
                    REFERENCES network_device_state(network_cidr, mac_address) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS device_ports (
                network_cidr VARCHAR(43) NOT NULL, mac_address CHAR(17) NOT NULL,
                port SMALLINT UNSIGNED NOT NULL, current_state VARCHAR(16) NOT NULL,
                last_result VARCHAR(16) NOT NULL, service_name VARCHAR(64) NULL,
                confidence VARCHAR(16) NULL, evidence VARCHAR(255) NULL,
                first_seen DATETIME NOT NULL, last_checked DATETIME NOT NULL,
                last_opened DATETIME NULL,
                PRIMARY KEY (network_cidr, mac_address, port),
                INDEX idx_ports_open (network_cidr, current_state),
                CONSTRAINT fk_ports_state FOREIGN KEY (network_cidr, mac_address)
                    REFERENCES network_device_state(network_cidr, mac_address) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS inventory_events (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, scan_id BIGINT UNSIGNED NOT NULL,
                network_cidr VARCHAR(43) NOT NULL, mac_address CHAR(17) NOT NULL,
                event_type VARCHAR(32) NOT NULL, subject_key VARCHAR(64) NOT NULL,
                port SMALLINT UNSIGNED NULL, old_value VARCHAR(255) NULL,
                new_value VARCHAR(255) NULL, occurred_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE INDEX uq_inventory_event (scan_id,mac_address,event_type,subject_key),
                INDEX idx_inventory_mac_time (mac_address,occurred_at),
                CONSTRAINT fk_inventory_scan FOREIGN KEY (scan_id)
                    REFERENCES scans(id) ON DELETE CASCADE,
                CONSTRAINT fk_inventory_state FOREIGN KEY (network_cidr, mac_address)
                    REFERENCES network_device_state(network_cidr, mac_address) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
            """CREATE TABLE IF NOT EXISTS inventory_applied (
                scan_id BIGINT UNSIGNED NOT NULL, applied_at DATETIME NOT NULL,
                PRIMARY KEY (scan_id),
                CONSTRAINT fk_inventory_applied_scan FOREIGN KEY (scan_id)
                    REFERENCES scans(id) ON DELETE CASCADE
            ) ENGINE=InnoDB""",
        )
        for statement in statements:
            cursor.execute(statement)
        connection.commit()
    finally:
        cursor.close()
    _apply_safe_migrations(connection, database)
    return connection


def _events_for_scan(cursor: Any, scan_id: int) -> tuple[DeviceEvent, ...]:
    cursor.execute(
        "SELECT event_type, mac_address, ip_address, previous_ip, occurred_at, network_cidr "
        "FROM device_events WHERE scan_id=%s ORDER BY id",
        (scan_id,),
    )
    return tuple(
        DeviceEvent(
            row["event_type"], row["mac_address"], row["ip_address"],
            row["occurred_at"], row["previous_ip"], row["network_cidr"]
        )
        for row in cursor.fetchall()
    )


def _history_diff(scan_id: int, events: tuple[DeviceEvent, ...]) -> HistoryDiff:
    return HistoryDiff(
        scan_id,
        tuple(e.mac for e in events if e.event_type == "NEW"),
        tuple(e.mac for e in events if e.event_type == "OFFLINE"),
        tuple(e.mac for e in events if e.event_type == "RECONNECTED"),
        events,
    )


def save_scan(
    connection: Any,
    interface: str,
    network: str,
    devices: Iterable[Any],
    *,
    healthy: bool = True,
    error_message: str | None = None,
    duration_seconds: float | None = None,
    scan_key: str | None = None,
    observed_at: datetime | None = None,
) -> HistoryDiff:
    """Persiste um scan idempotente; scans sem saúde não alteram presença."""

    scan_key = scan_key or new_scan_key()
    current_by_mac = {normalize_mac(device.mac): device for device in devices}
    device_list = list(current_by_mac.values())
    cursor = connection.cursor(dictionary=True)
    events: list[DeviceEvent] = []
    try:
        cursor.execute("SELECT id FROM scans WHERE scan_key=%s", (scan_key,))
        existing = cursor.fetchone()
        if existing:
            scan_id = int(existing["id"])
            return _history_diff(scan_id, _events_for_scan(cursor, scan_id))

        if observed_at is None:
            cursor.execute("SELECT NOW() AS observed_at")
            observed_at = cursor.fetchone()["observed_at"]
        cursor.execute(
            "INSERT INTO scans (scan_key, interface_name, network_cidr, device_count, "
            "scan_status, error_message, duration_seconds) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (
                scan_key, interface, network, len(device_list),
                "success" if healthy else "failed", error_message, duration_seconds,
            ),
        )
        scan_id = int(cursor.lastrowid)
        if not healthy:
            connection.commit()
            return _history_diff(scan_id, ())

        if device_list:
            cursor.executemany(
                "INSERT INTO scan_devices (scan_id,ip_address,mac_address,vendor) "
                "VALUES (%s,%s,%s,%s)",
                [(scan_id, d.ip, normalize_mac(d.mac), d.vendor) for d in device_list],
            )

        cursor.execute(
            "SELECT mac_address,status,current_ip,missing_checks FROM network_device_state "
            "WHERE network_cidr=%s FOR UPDATE",
            (network,),
        )
        known = {row["mac_address"]: row for row in cursor.fetchall()}
        for mac, device in current_by_mac.items():
            cursor.execute(
                "INSERT INTO devices (mac_address,vendor,status,current_ip,current_network,"
                "first_seen,last_seen,missing_checks) VALUES (%s,%s,'online',%s,%s,%s,%s,0) "
                "ON DUPLICATE KEY UPDATE vendor=VALUES(vendor),last_seen=VALUES(last_seen)",
                (mac, device.vendor, device.ip, network, observed_at, observed_at),
            )
            previous = known.get(mac)
            if previous is None:
                cursor.execute(
                    "INSERT INTO network_device_state "
                    "(network_cidr,mac_address,status,current_ip,first_seen,last_seen,missing_checks) "
                    "VALUES (%s,%s,'online',%s,%s,%s,0)",
                    (network, mac, device.ip, observed_at, observed_at),
                )
                events.append(DeviceEvent("NEW", mac, device.ip, observed_at, network=network))
            else:
                _status, _misses, presence_event = advance_presence(
                    previous["status"], int(previous["missing_checks"]), seen=True
                )
                if presence_event == "RECONNECTED":
                    events.append(
                        DeviceEvent("RECONNECTED", mac, device.ip, observed_at, network=network)
                    )
                if previous["current_ip"] and previous["current_ip"] != device.ip:
                    events.append(
                        DeviceEvent(
                            "IP_CHANGED", mac, device.ip, observed_at,
                            previous["current_ip"], network,
                        )
                    )
                cursor.execute(
                    "UPDATE network_device_state SET status='online',current_ip=%s,"
                    "last_seen=%s,missing_checks=0 WHERE network_cidr=%s AND mac_address=%s",
                    (device.ip, observed_at, network, mac),
                )
            cursor.execute(
                "INSERT INTO network_device_ips "
                "(network_cidr,mac_address,ip_address,first_seen,last_seen,sightings) "
                "VALUES (%s,%s,%s,%s,%s,1) ON DUPLICATE KEY UPDATE "
                "last_seen=VALUES(last_seen),sightings=sightings+1",
                (network, mac, device.ip, observed_at, observed_at),
            )

        for mac, previous in known.items():
            if mac in current_by_mac or previous["status"] == "offline":
                continue
            status, misses, presence_event = advance_presence(
                previous["status"], int(previous["missing_checks"]), seen=False
            )
            cursor.execute(
                "UPDATE network_device_state SET status=%s,missing_checks=%s "
                "WHERE network_cidr=%s AND mac_address=%s",
                (status, misses, network, mac),
            )
            if presence_event == "OFFLINE":
                events.append(
                    DeviceEvent(
                        "OFFLINE", mac, previous["current_ip"], observed_at, network=network
                    )
                )

        for event in events:
            cursor.execute(
                "INSERT INTO device_events (mac_address,scan_id,event_type,ip_address,"
                "previous_ip,occurred_at,network_cidr) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (
                    event.mac, scan_id, event.event_type, event.ip,
                    event.previous_ip, event.occurred_at, network,
                ),
            )
        connection.commit()
        return _history_diff(scan_id, tuple(events))
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()


def save_inventory(
    connection: Any,
    scan_id: int,
    network: str,
    discoveries: Iterable[Any],
    *,
    observed_at: datetime,
) -> tuple[InventoryEvent, ...]:
    """Salva hostname/portas uma única vez por scan e registra mudanças."""

    items = [item for item in discoveries if getattr(item, "mac", None)]
    cursor = connection.cursor(dictionary=True)
    events: list[InventoryEvent] = []
    try:
        cursor.execute("SELECT 1 FROM inventory_applied WHERE scan_id=%s", (scan_id,))
        if cursor.fetchone():
            cursor.execute(
                "SELECT event_type,network_cidr,mac_address,port,old_value,new_value,occurred_at "
                "FROM inventory_events WHERE scan_id=%s ORDER BY id",
                (scan_id,),
            )
            return tuple(
                InventoryEvent(
                    row["event_type"], row["network_cidr"], row["mac_address"],
                    row["port"], row["old_value"], row["new_value"], row["occurred_at"]
                )
                for row in cursor.fetchall()
            )

        for item in items:
            mac = normalize_mac(item.mac)
            hostname = getattr(item, "hostname", None)
            if hostname:
                cursor.execute(
                    "SELECT hostname FROM device_hostnames "
                    "WHERE network_cidr=%s AND mac_address=%s "
                    "ORDER BY last_seen DESC LIMIT 1",
                    (network, mac),
                )
                previous = cursor.fetchone()
                previous_hostname = previous["hostname"] if previous else None
                cursor.execute(
                    "INSERT INTO device_hostnames "
                    "(network_cidr,mac_address,hostname,source,first_seen,last_seen,sightings) "
                    "VALUES (%s,%s,%s,%s,%s,%s,1) ON DUPLICATE KEY UPDATE "
                    "source=VALUES(source),last_seen=VALUES(last_seen),sightings=sightings+1",
                    (
                        network, mac, hostname, getattr(item, "hostname_source", None),
                        observed_at, observed_at,
                    ),
                )
                if previous_hostname != hostname:
                    event_type = "HOSTNAME_DISCOVERED" if previous_hostname is None else "HOSTNAME_CHANGED"
                    events.append(
                        InventoryEvent(
                            event_type, network, mac, None,
                            previous_hostname, hostname, observed_at,
                        )
                    )

            for port_result in getattr(item, "ports", ()):
                cursor.execute(
                    "SELECT current_state,service_name,confidence FROM device_ports "
                    "WHERE network_cidr=%s AND mac_address=%s AND port=%s FOR UPDATE",
                    (network, mac, port_result.port),
                )
                previous = cursor.fetchone()
                previous_state = previous["current_state"] if previous else None
                previous_service = previous["service_name"] if previous else None
                # Timeout/filtro não prova fechamento: preserva o último estado
                # confirmado, mas registra o resultado da tentativa.
                current_state, port_event, old_value, new_value = classify_port_change(
                    previous_state,
                    previous_service,
                    port_result.state,
                    port_result.service,
                )
                cursor.execute(
                    "INSERT INTO device_ports "
                    "(network_cidr,mac_address,port,current_state,last_result,service_name,"
                    "confidence,evidence,first_seen,last_checked,last_opened) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON DUPLICATE KEY UPDATE current_state=VALUES(current_state),"
                    "last_result=VALUES(last_result),service_name=COALESCE(VALUES(service_name),service_name),"
                    "confidence=COALESCE(VALUES(confidence),confidence),"
                    "evidence=COALESCE(VALUES(evidence),evidence),last_checked=VALUES(last_checked),"
                    "last_opened=IF(VALUES(current_state)='open',VALUES(last_checked),last_opened)",
                    (
                        network, mac, port_result.port, current_state, port_result.state,
                        port_result.service, port_result.confidence, port_result.evidence,
                        observed_at, observed_at,
                        observed_at if port_result.state == "open" else None,
                    ),
                )
                if port_event:
                    events.append(
                        InventoryEvent(
                            port_event, network, mac, port_result.port,
                            old_value, new_value, observed_at,
                        )
                    )

        for event in events:
            subject = "hostname" if event.port is None else f"tcp:{event.port}"
            cursor.execute(
                "INSERT IGNORE INTO inventory_events "
                "(scan_id,network_cidr,mac_address,event_type,subject_key,port,"
                "old_value,new_value,occurred_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    scan_id, event.network, event.mac, event.event_type, subject,
                    event.port, event.old_value, event.new_value, event.occurred_at,
                ),
            )
        cursor.execute(
            "INSERT INTO inventory_applied (scan_id,applied_at) VALUES (%s,%s)",
            (scan_id, observed_at),
        )
        connection.commit()
        return tuple(events)
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()


def get_device_history(
    connection: Any, mac: str, network: str | None = None
) -> DeviceHistory | None:
    normalized = normalize_mac(mac)
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT mac_address,vendor,first_seen,last_seen FROM devices WHERE mac_address=%s",
            (normalized,),
        )
        device = cursor.fetchone()
        if device is None:
            return None
        clause = " AND network_cidr=%s" if network else ""
        params = (normalized, network) if network else (normalized,)
        cursor.execute(
            "SELECT network_cidr,status,current_ip,first_seen,last_seen,missing_checks "
            f"FROM network_device_state WHERE mac_address=%s{clause} ORDER BY network_cidr",
            params,
        )
        states = tuple(
            NetworkState(
                r["network_cidr"], r["status"], r["current_ip"], r["first_seen"],
                r["last_seen"], r["missing_checks"]
            )
            for r in cursor.fetchall()
        )
        cursor.execute(
            "SELECT network_cidr,ip_address,first_seen,last_seen,sightings "
            f"FROM network_device_ips WHERE mac_address=%s{clause} "
            "ORDER BY network_cidr,first_seen",
            params,
        )
        ips = tuple(
            (r["network_cidr"], r["ip_address"], r["first_seen"], r["last_seen"], r["sightings"])
            for r in cursor.fetchall()
        )
        cursor.execute(
            "SELECT event_type,ip_address,previous_ip,occurred_at,network_cidr "
            f"FROM device_events WHERE mac_address=%s{clause} ORDER BY occurred_at DESC,id DESC",
            params,
        )
        events = tuple(
            DeviceEvent(
                r["event_type"], normalized, r["ip_address"], r["occurred_at"],
                r["previous_ip"], r["network_cidr"]
            )
            for r in cursor.fetchall()
        )
        cursor.execute(
            "SELECT network_cidr,hostname,source,first_seen,last_seen,sightings "
            f"FROM device_hostnames WHERE mac_address=%s{clause} "
            "ORDER BY network_cidr,last_seen DESC",
            params,
        )
        hostnames = tuple(
            (
                r["network_cidr"], r["hostname"], r["source"], r["first_seen"],
                r["last_seen"], r["sightings"],
            )
            for r in cursor.fetchall()
        )
        cursor.execute(
            "SELECT network_cidr,port,current_state,last_result,service_name,confidence,last_checked "
            f"FROM device_ports WHERE mac_address=%s{clause} "
            "ORDER BY network_cidr,port",
            params,
        )
        ports = tuple(
            (
                r["network_cidr"], r["port"], r["current_state"], r["last_result"],
                r["service_name"], r["confidence"], r["last_checked"],
            )
            for r in cursor.fetchall()
        )
        cursor.execute(
            "SELECT network_cidr,event_type,port,old_value,new_value,occurred_at "
            f"FROM inventory_events WHERE mac_address=%s{clause} "
            "ORDER BY occurred_at DESC,id DESC",
            params,
        )
        inventory_events = tuple(
            (
                r["network_cidr"], r["event_type"], r["port"], r["old_value"],
                r["new_value"], r["occurred_at"],
            )
            for r in cursor.fetchall()
        )
        return DeviceHistory(
            device["mac_address"], device["vendor"], device["first_seen"],
            device["last_seen"], states, ips, events,
            hostnames, ports, inventory_events,
        )
    finally:
        cursor.close()


def acquire_scan_lock(connection: Any, network: str) -> bool:
    """Obtém lock MySQL entre processos para impedir scan simultâneo da rede."""

    cursor = connection.cursor()
    try:
        cursor.execute("SELECT GET_LOCK(%s, 0)", (f"network_mapper:{network}",))
        row = cursor.fetchone()
        return bool(row and row[0] == 1)
    finally:
        cursor.close()


def get_online_device_count(connection: Any, network: str) -> int:
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM network_device_state "
            "WHERE network_cidr=%s AND status='online'",
            (network,),
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        cursor.close()


def release_scan_lock(connection: Any, network: str) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT RELEASE_LOCK(%s)", (f"network_mapper:{network}",))
        cursor.fetchone()
    finally:
        cursor.close()


class ResilientMySQL:
    """Executa operações com reconexão progressiva e retry idempotente."""

    def __init__(
        self,
        config: dict[str, Any],
        *,
        max_attempts: int = 5,
        base_delay: float = 1.0,
        connect_factory: Callable[[dict[str, Any]], Any] = connect_mysql,
        sleep: Callable[[float], None] = time.sleep,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self._connect_factory = connect_factory
        self._sleep = sleep
        self._logger = logger or logging.getLogger(__name__)
        self._connection: Any | None = None

    def _close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None

    @staticmethod
    def _retryable(exc: Exception) -> bool:
        errno = getattr(exc, "errno", None)
        return errno in RETRYABLE_MYSQL_ERRORS or isinstance(exc, (ConnectionError, TimeoutError))

    def run(self, operation: Callable[[Any], T]) -> T:
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                if self._connection is None:
                    self._connection = self._connect_factory(self.config)
                    self._logger.info("Conexão MySQL estabelecida")
                return operation(self._connection)
            except Exception as exc:
                last_error = exc
                if not self._retryable(exc) or attempt == self.max_attempts:
                    raise
                self._close()
                delay = min(self.base_delay * (2 ** (attempt - 1)), 30.0)
                self._logger.warning(
                    "MySQL indisponível (%s). Reconexão %d/%d em %.1fs",
                    exc, attempt + 1, self.max_attempts, delay,
                )
                self._sleep(delay)
        assert last_error is not None
        raise last_error

    def close(self) -> None:
        self._close()
