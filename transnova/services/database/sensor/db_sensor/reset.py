"""Put the deception back to its starting state between demo runs.

    python -m db_sensor.reset

Revokes every adaptive table from the attacker account and clears the sensor's behaviour
memory. It keeps the log position, so old audit lines are not reprocessed, and keeps all events
already at the collector. Stop the sensor first: it holds this state in memory.
"""

from __future__ import annotations

import sys

from .adaptive import GrantBackend
from .config import Settings, load_rules
from .state import SensorState


def main() -> int:
    settings = Settings.from_env()
    rules = load_rules(settings.rules_path)
    backend = GrantBackend(settings)
    for table in rules["adaptive_tables"]:
        if backend.has_grant(table):
            print(backend.revoke(table))
    SensorState(settings.data_dir).reset_deception()
    print("deception reset")
    return 0


if __name__ == "__main__":
    sys.exit(main())
