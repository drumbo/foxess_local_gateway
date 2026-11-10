#!/usr/bin/env python3
"""Run the local FoxESS M1/Q1 cloud emulator."""

from __future__ import annotations

import argparse
import asyncio
import signal
from pathlib import Path

from .config import load_config
from .server import FoxessLocalCloud


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()

    app = FoxessLocalCloud(load_config(args.config))
    try:
        asyncio.run(_serve(app))
    except KeyboardInterrupt:
        pass
    finally:
        app.logger.close()
        app.mqtt.close()
    return 0


async def _serve(app: FoxessLocalCloud) -> None:
    """Run the daemon, converting SIGTERM/SIGINT into a clean cancellation so
    the listeners close and MQTT is disconnected deliberately (systemd stops
    services with SIGTERM)."""
    task = asyncio.ensure_future(app.run())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except NotImplementedError:  # e.g. Windows
            pass
    try:
        await task
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    raise SystemExit(main())
