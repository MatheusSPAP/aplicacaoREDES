"""Pool MySQL da API; cada requisição recebe sua própria conexão."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import Any

from .config import APISettings


class DatabasePool:
    def __init__(self, settings: APISettings) -> None:
        self.settings = settings
        self._pool: Any | None = None
        self._lock = threading.Lock()

    def _get_pool(self) -> Any:
        if self._pool is None:
            with self._lock:
                if self._pool is None:
                    from mysql.connector.pooling import MySQLConnectionPool

                    self._pool = MySQLConnectionPool(
                        pool_name="network_mapper_api",
                        pool_size=self.settings.pool_size,
                        pool_reset_session=True,
                        **self.settings.mysql,
                    )
        return self._pool

    def connection(self) -> Any:
        return self._get_pool().get_connection()

    def close(self) -> None:
        # mysql-connector não oferece close público para o pool. Conexões devolvidas
        # por close() são resetadas e permanecem gerenciadas internamente.
        self._pool = None


def connection_dependency(pool: DatabasePool) -> Iterator[Any]:
    connection = pool.connection()
    try:
        yield connection
    finally:
        connection.close()
