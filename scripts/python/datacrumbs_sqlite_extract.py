#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def load_kv_table(connection: sqlite3.Connection, table_name: str) -> dict[str, str]:
    return {
        str(key): str(value)
        for key, value in connection.execute(f"SELECT key, value FROM {table_name}")
    }


def load_probe_status(connection: sqlite3.Connection, status: str) -> dict[str, dict[str, list[str]]]:
    grouped: dict[str, dict[str, list[str]]] = {}
    rows = connection.execute(
        """
        SELECT probe_group, scope_key, function_name
        FROM runtime_probe_status
        WHERE status = ?
        ORDER BY probe_group, scope_key, function_name
        """,
        (status,),
    )
    for probe_group, scope_key, function_name in rows:
        grouped.setdefault(str(probe_group), {}).setdefault(str(scope_key), []).append(
            str(function_name)
        )
    return grouped


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract datacrumbs system configuration or probe status tables from a SQLite database"
    )
    parser.add_argument("--database", required=True, help="Path to the datacrumbs sqlite database")
    parser.add_argument(
        "--section",
        required=True,
        choices=("system-configuration", "summary", "valid-probes", "invalid-probes"),
        help="Which logical section to extract",
    )
    args = parser.parse_args()

    database_path = Path(args.database).resolve()
    with sqlite3.connect(database_path) as connection:
        if args.section == "system-configuration":
            payload = load_kv_table(connection, "system_configuration")
        elif args.section == "summary":
            payload = load_kv_table(connection, "summary")
        elif args.section == "valid-probes":
            payload = load_probe_status(connection, "successful")
        else:
            payload = load_probe_status(connection, "invalid")

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
