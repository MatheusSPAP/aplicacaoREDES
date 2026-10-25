"""Consultas históricas precisas, paginadas e parametrizadas."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median
from typing import Any, Iterable


PRESENCE_EVENT_TYPES = {"NEW", "OFFLINE", "RECONNECTED", "IP_CHANGED"}
INVENTORY_EVENT_TYPES = {
    "HOSTNAME_DISCOVERED", "HOSTNAME_CHANGED", "PORT_OPENED", "PORT_CLOSED",
    "SERVICE_CHANGED",
}
CHANGE_EVENT_TYPES = {
    "IP_CHANGED", "HOSTNAME_CHANGED", "PORT_OPENED", "PORT_CLOSED",
    "SERVICE_CHANGED",
}


@dataclass(frozen=True)
class QueryFilters:
    network: str | None = None
    mac: str | None = None
    ip: str | None = None
    status: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    limit: int = 1000
    offset: int = 0


def parse_datetime(value: str | None, *, end_of_day: bool = False) -> datetime | None:
    if not value:
        return None
    formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")
    for date_format in formats:
        try:
            parsed = datetime.strptime(value, date_format)
            if date_format == "%Y-%m-%d" and end_of_day:
                parsed += timedelta(days=1) - timedelta(microseconds=1)
            return parsed
        except ValueError:
            continue
    raise ValueError(
        f"data inválida: {value!r}; use AAAA-MM-DD ou AAAA-MM-DD HH:MM:SS"
    )


def _append_equal(
    clauses: list[str], params: list[Any], column: str, value: Any
) -> None:
    if value is not None:
        clauses.append(f"{column}=%s")
        params.append(value)


def fetch_inventory(connection: Any, filters: QueryFilters) -> list[dict[str, Any]]:
    """Inclui dispositivos cujo intervalo observado sobrepõe o período pedido."""

    clauses: list[str] = []
    params: list[Any] = []
    _append_equal(clauses, params, "s.network_cidr", filters.network)
    _append_equal(clauses, params, "s.mac_address", filters.mac)
    _append_equal(clauses, params, "s.status", filters.status)

    if filters.start:
        clauses.append(
            "(s.last_seen>=%s OR EXISTS (SELECT 1 FROM device_events pe "
            "WHERE pe.network_cidr=s.network_cidr AND pe.mac_address=s.mac_address "
            "AND pe.occurred_at>=%s" + (" AND pe.occurred_at<=%s" if filters.end else "") + "))"
        )
        params.extend([filters.start, filters.start])
        if filters.end:
            params.append(filters.end)
    if filters.end:
        clauses.append("s.first_seen<=%s")
        params.append(filters.end)
    if filters.ip:
        ip_overlap = [
            "i.network_cidr=s.network_cidr",
            "i.mac_address=s.mac_address",
            "i.ip_address=%s",
        ]
        params.append(filters.ip)
        if filters.start:
            ip_overlap.append("i.last_seen>=%s")
            params.append(filters.start)
        if filters.end:
            ip_overlap.append("i.first_seen<=%s")
            params.append(filters.end)
        clauses.append(
            "EXISTS (SELECT 1 FROM network_device_ips i WHERE "
            + " AND ".join(ip_overlap)
            + ")"
        )

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT s.network_cidr AS network,s.mac_address AS mac,s.current_ip AS ip,"
            "d.vendor,s.status,s.first_seen,s.last_seen,s.missing_checks,"
            "(SELECT h.hostname FROM device_hostnames h WHERE h.network_cidr=s.network_cidr "
            "AND h.mac_address=s.mac_address ORDER BY h.last_seen DESC LIMIT 1) AS hostname "
            "FROM network_device_state s JOIN devices d ON d.mac_address=s.mac_address"
            f"{where} ORDER BY s.network_cidr,s.current_ip,s.mac_address LIMIT %s OFFSET %s",
            (*params, filters.limit, filters.offset),
        )
        return list(cursor.fetchall())
    finally:
        cursor.close()


def _event_clauses(
    filters: QueryFilters,
    *,
    alias: str,
    ip_expression: str,
    event_types: set[str] | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    _append_equal(clauses, params, f"{alias}.network_cidr", filters.network)
    _append_equal(clauses, params, f"{alias}.mac_address", filters.mac)
    if filters.ip:
        clauses.append(ip_expression)
        params.extend([filters.ip] * ip_expression.count("%s"))
    if filters.status:
        clauses.append("ns.status=%s")
        params.append(filters.status)
    if filters.start:
        clauses.append(f"{alias}.occurred_at>=%s")
        params.append(filters.start)
    if filters.end:
        clauses.append(f"{alias}.occurred_at<=%s")
        params.append(filters.end)
    if event_types:
        placeholders = ",".join(["%s"] * len(event_types))
        clauses.append(f"{alias}.event_type IN ({placeholders})")
        params.extend(sorted(event_types))
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def fetch_events(
    connection: Any,
    filters: QueryFilters,
    *,
    event_types: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Une presença e inventário antes de ordenar, limitar e paginar."""

    presence_types = event_types & PRESENCE_EVENT_TYPES if event_types else None
    inventory_types = event_types & INVENTORY_EVENT_TYPES if event_types else None
    selects: list[str] = []
    params: list[Any] = []
    if event_types is None or presence_types:
        where, values = _event_clauses(
            filters,
            alias="e",
            ip_expression="(e.ip_address=%s OR e.previous_ip=%s)",
            event_types=presence_types,
        )
        selects.append(
            "SELECT 'presence' AS category,e.event_type,e.network_cidr AS network,"
            "e.mac_address AS mac,e.ip_address AS ip,NULL AS port,e.previous_ip AS old_value,"
            "e.ip_address AS new_value,e.occurred_at FROM device_events e "
            "JOIN network_device_state ns ON ns.network_cidr=e.network_cidr "
            f"AND ns.mac_address=e.mac_address{where}"
        )
        params.extend(values)
    if event_types is None or inventory_types:
        where, values = _event_clauses(
            filters,
            alias="e",
            ip_expression="sd.ip_address=%s",
            event_types=inventory_types,
        )
        selects.append(
            "SELECT 'inventory' AS category,e.event_type,e.network_cidr AS network,"
            "e.mac_address AS mac,sd.ip_address AS ip,e.port,e.old_value,e.new_value,e.occurred_at "
            "FROM inventory_events e JOIN network_device_state ns "
            "ON ns.network_cidr=e.network_cidr AND ns.mac_address=e.mac_address "
            "LEFT JOIN scan_devices sd ON sd.scan_id=e.scan_id AND sd.mac_address=e.mac_address"
            f"{where}"
        )
        params.extend(values)
    if not selects:
        return []
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT * FROM (" + " UNION ALL ".join(selects) + ") history "
            "ORDER BY occurred_at DESC,category,event_type LIMIT %s OFFSET %s",
            (*params, filters.limit, filters.offset),
        )
        return list(cursor.fetchall())
    finally:
        cursor.close()


def fetch_top_disconnects(connection: Any, filters: QueryFilters) -> list[dict[str, Any]]:
    clauses = ["e.event_type='OFFLINE'"]
    params: list[Any] = []
    _append_equal(clauses, params, "e.network_cidr", filters.network)
    _append_equal(clauses, params, "e.mac_address", filters.mac)
    _append_equal(clauses, params, "ns.status", filters.status)
    if filters.ip:
        clauses.append("e.ip_address=%s")
        params.append(filters.ip)
    if filters.start:
        clauses.append("e.occurred_at>=%s")
        params.append(filters.start)
    if filters.end:
        clauses.append("e.occurred_at<=%s")
        params.append(filters.end)
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT e.network_cidr AS network,e.mac_address AS mac,COUNT(*) AS disconnections,"
            "MAX(e.occurred_at) AS last_disconnection FROM device_events e "
            "JOIN network_device_state ns ON ns.network_cidr=e.network_cidr "
            "AND ns.mac_address=e.mac_address WHERE " + " AND ".join(clauses) +
            " GROUP BY e.network_cidr,e.mac_address "
            "ORDER BY disconnections DESC,last_disconnection DESC LIMIT %s OFFSET %s",
            (*params, filters.limit, filters.offset),
        )
        return list(cursor.fetchall())
    finally:
        cursor.close()


def fetch_networks(connection: Any) -> list[dict[str, Any]]:
    """Resume as redes conhecidas e seus estados atuais."""

    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT network_cidr AS network,COUNT(*) AS devices,"
            "SUM(status='online') AS online,SUM(status='offline') AS offline,"
            "MIN(first_seen) AS first_seen,MAX(last_seen) AS last_seen "
            "FROM network_device_state GROUP BY network_cidr ORDER BY network_cidr"
        )
        return list(cursor.fetchall())
    finally:
        cursor.close()


def fetch_device_ports(
    connection: Any, mac: str, network: str | None = None
) -> list[dict[str, Any]]:
    """Retorna portas e serviços persistidos, sem executar scanner TCP."""

    clauses = ["mac_address=%s"]
    params: list[Any] = [mac]
    if network:
        clauses.append("network_cidr=%s")
        params.append(network)
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT network_cidr AS network,mac_address AS mac,port,current_state AS state,"
            "last_result,service_name AS service,confidence,evidence,first_seen,last_checked,"
            "last_opened FROM device_ports WHERE " + " AND ".join(clauses) +
            " ORDER BY network_cidr,port",
            tuple(params),
        )
        return list(cursor.fetchall())
    finally:
        cursor.close()


def _state_after(state: str | None, event_type: str) -> str | None:
    if event_type in {"NEW", "RECONNECTED"}:
        return "online"
    if event_type == "OFFLINE":
        return "offline"
    return state


def calculate_availability(
    events: Iterable[dict[str, Any]],
    scan_times: Iterable[datetime],
    start: datetime,
    end: datetime,
    *,
    initial_state: str | None,
) -> dict[str, float | None]:
    """Calcula tempo online apenas onde houve cobertura de monitoramento."""

    total_seconds = max(0.0, (end - start).total_seconds())
    times = sorted({time for time in scan_times if start <= time <= end})
    if total_seconds == 0 or len(times) < 2:
        return {
            "estimated_percent": None,
            "monitoring_coverage_percent": 0.0,
            "online_seconds": 0.0,
            "offline_seconds": 0.0,
            "unknown_seconds": total_seconds,
        }
    deltas = [
        (right - left).total_seconds()
        for left, right in zip(times, times[1:])
        if right > left
    ]
    expected = median(deltas) if deltas else 0.0
    maximum_gap = max(expected * 3.0, 60.0)
    coverage = [
        (left, right)
        for left, right in zip(times, times[1:])
        if (right - left).total_seconds() <= maximum_gap
    ]
    ordered_events = sorted(
        (event for event in events if event["occurred_at"] <= end),
        key=lambda event: event["occurred_at"],
    )
    online_seconds = offline_seconds = covered_seconds = 0.0
    for left, right in coverage:
        state = initial_state
        for event in ordered_events:
            if event["occurred_at"] <= left:
                state = _state_after(state, event["event_type"])
            else:
                break
        cursor_time = left
        for event in ordered_events:
            at = event["occurred_at"]
            if at <= left or at >= right:
                continue
            seconds = (at - cursor_time).total_seconds()
            if state == "online":
                online_seconds += seconds
            elif state == "offline":
                offline_seconds += seconds
            cursor_time = at
            state = _state_after(state, event["event_type"])
        seconds = (right - cursor_time).total_seconds()
        if state == "online":
            online_seconds += seconds
        elif state == "offline":
            offline_seconds += seconds
        covered_seconds += (right - left).total_seconds()
    known_seconds = online_seconds + offline_seconds
    return {
        "estimated_percent": (
            round(100.0 * online_seconds / known_seconds, 2) if known_seconds else None
        ),
        "monitoring_coverage_percent": round(100.0 * covered_seconds / total_seconds, 2),
        "online_seconds": round(online_seconds, 2),
        "offline_seconds": round(offline_seconds, 2),
        "unknown_seconds": round(max(0.0, total_seconds - known_seconds), 2),
    }


def estimate_availability(
    events: Iterable[dict[str, Any]],
    start: datetime,
    end: datetime,
    *,
    initially_online: bool,
) -> float:
    """Compatibilidade: estimativa contínua antiga, sem inferir cobertura."""

    result = calculate_availability(
        events,
        (start, end),
        start,
        end,
        initial_state="online" if initially_online else "offline",
    )
    return float(result["estimated_percent"] or 0.0)


def fetch_availability(connection: Any, filters: QueryFilters) -> list[dict[str, Any]]:
    inventory = fetch_inventory(connection, filters)
    if not inventory:
        return []
    cursor = connection.cursor(dictionary=True)
    try:
        now = datetime.now()
        end = filters.end or now
        starts = {
            (item["network"], item["mac"]): filters.start or item["first_seen"]
            for item in inventory
        }
        earliest = min(starts.values())
        networks = sorted({item["network"] for item in inventory})
        network_placeholders = ",".join(["%s"] * len(networks))
        cursor.execute(
            "SELECT network_cidr AS network,scanned_at FROM scans "
            f"WHERE scan_status='success' AND network_cidr IN ({network_placeholders}) "
            "AND scanned_at BETWEEN %s AND %s ORDER BY network_cidr,scanned_at",
            (*networks, earliest, end),
        )
        scan_times: dict[str, list[datetime]] = {}
        for row in cursor.fetchall():
            scan_times.setdefault(row["network"], []).append(row["scanned_at"])

        key_placeholders = ",".join(["(%s,%s)"] * len(inventory))
        key_params = [value for item in inventory for value in (item["network"], item["mac"])]
        cursor.execute(
            "SELECT s.network_cidr AS network,sd.mac_address AS mac,s.scanned_at "
            "FROM scans s JOIN scan_devices sd ON sd.scan_id=s.id "
            "WHERE s.scan_status='success' "
            f"AND (s.network_cidr,sd.mac_address) IN ({key_placeholders}) "
            "AND s.scanned_at BETWEEN %s AND %s",
            (*key_params, earliest, end),
        )
        responses_by_key: dict[tuple[str, str], list[datetime]] = {}
        for row in cursor.fetchall():
            responses_by_key.setdefault((row["network"], row["mac"]), []).append(row["scanned_at"])

        cursor.execute(
            "SELECT e.network_cidr AS network,e.mac_address AS mac,e.event_type,e.occurred_at "
            "FROM device_events e JOIN ("
            "SELECT network_cidr,mac_address,MAX(occurred_at) AS occurred_at "
            "FROM device_events WHERE event_type IN ('NEW','OFFLINE','RECONNECTED') "
            f"AND (network_cidr,mac_address) IN ({key_placeholders}) AND occurred_at<%s "
            "GROUP BY network_cidr,mac_address) prior "
            "ON prior.network_cidr=e.network_cidr AND prior.mac_address=e.mac_address "
            "AND prior.occurred_at=e.occurred_at "
            "WHERE e.event_type IN ('NEW','OFFLINE','RECONNECTED')",
            (*key_params, earliest),
        )
        events_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for event in cursor.fetchall():
            events_by_key.setdefault((event["network"], event["mac"]), []).append(event)
        cursor.execute(
            "SELECT network_cidr AS network,mac_address AS mac,event_type,occurred_at "
            "FROM device_events WHERE event_type IN ('NEW','OFFLINE','RECONNECTED') "
            f"AND (network_cidr,mac_address) IN ({key_placeholders}) "
            "AND occurred_at BETWEEN %s AND %s ORDER BY occurred_at",
            (*key_params, earliest, end),
        )
        for event in cursor.fetchall():
            events_by_key.setdefault((event["network"], event["mac"]), []).append(event)

        output: list[dict[str, Any]] = []
        for device in inventory:
            key = (device["network"], device["mac"])
            start = starts[key]
            all_events = sorted(events_by_key.get(key, []), key=lambda row: row["occurred_at"])
            initial_state: str | None = None
            period_events: list[dict[str, Any]] = []
            for event in all_events:
                if event["occurred_at"] <= start:
                    initial_state = _state_after(initial_state, event["event_type"])
                else:
                    period_events.append(event)
            relevant_scans = [
                at for at in scan_times.get(device["network"], []) if start <= at <= end
            ]
            samples = len(relevant_scans)
            present = sum(start <= at <= end for at in responses_by_key.get(key, []))
            availability = calculate_availability(
                period_events,
                relevant_scans,
                start,
                end,
                initial_state=initial_state,
            )
            output.append(
                {
                    "network": device["network"],
                    "mac": device["mac"],
                    "ip": device["ip"],
                    "hostname": device["hostname"],
                    "status": device["status"],
                    "period_start": start,
                    "period_end": end,
                    "healthy_samples": samples,
                    "response_samples": present,
                    "response_percent": round(100.0 * present / samples, 2) if samples else None,
                    "estimated_availability_percent": availability["estimated_percent"],
                    "monitoring_coverage_percent": availability["monitoring_coverage_percent"],
                    "unknown_seconds": availability["unknown_seconds"],
                }
            )
        return output
    finally:
        cursor.close()
