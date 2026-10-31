"""A real local SQLite effect/outbox for the native JSON Execute adapter."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    path = Path(args.database)
    path.parent.mkdir(parents=True, exist_ok=True)
    event = json.load(sys.stdin)
    plan = json.dumps(
        {
            key: event.get(key)
            for key in ("principal", "resource", "action", "destination", "arguments")
        },
        sort_keys=True,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS effects (nonce TEXT PRIMARY KEY, plan TEXT NOT NULL)"
        )
        connection.execute("BEGIN IMMEDIATE")
        prior = connection.execute(
            "SELECT plan FROM effects WHERE nonce=?", (event["nonce"],)
        ).fetchone()
        if prior and prior[0] != plan:
            raise ValueError("Effect nonce rebound to different arguments")
        if prior is None:
            connection.execute(
                "INSERT INTO effects VALUES (?,?)", (event["nonce"], plan)
            )
    print(
        json.dumps(
            dict(committed=True, nonce=event["nonce"], replayed=prior is not None)
        )
    )


if __name__ == "__main__":
    main()
