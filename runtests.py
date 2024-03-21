#!/usr/bin/env python

import json
import logging
import os
import socket
import sys
from contextlib import suppress
from threading import Thread

import paramiko

import blacknet.console  # noqa: F401
from blacknet.master import BlacknetMasterServer
from blacknet.scrubber import BlacknetScrubber
from blacknet.sensor import BlacknetSensor
from blacknet.server import BlacknetServer  # noqa: F401
from blacknet.updater import BlacknetGeoUpdater

SCRUBBER_STATS_FILE = "tests/generated/stats_general.json"
HONEYPOT_CONFIG_FILE = "tests/blacknet-honeypot.cfg"
MASTER_CONFIG_FILE = "tests/blacknet.cfg"
CLIENT_SSH_KEY = "tests/ssh_key"


def runtests_ssh_serve(bns: BlacknetSensor) -> None:
    """Thread entry point, runs the sensor."""
    bns.do_ping()
    bns.serve()


def runtests_main_serve(bns: BlacknetMasterServer) -> None:
    """Thread entry point, runs the master server."""
    bns.serve()


def runtests_ssh_client() -> None:
    """Simulate a real SSH client trying to authenticate."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 2200))

    t = paramiko.Transport(sock)
    t.start_client()

    with suppress(BaseException):
        ssh_key = paramiko.RSAKey(filename=CLIENT_SSH_KEY)
        t.auth_publickey("blacknet", ssh_key)

    for suffix in ["0", "1", "a", "b", "c", "é", "&", "L", ")", "€", "\xfe", "\xa8"]:
        with suppress(Exception):
            password = "password_%s" % suffix
            t.auth_password("blacknet", password)
    t.close()


def runtests_update() -> None:
    """Update database geolocation from local samples."""
    bnu = BlacknetGeoUpdater(MASTER_CONFIG_FILE)
    bnu.update()


def runtests_scrubber() -> None:
    """Run the database scrubber."""
    bns = BlacknetScrubber(MASTER_CONFIG_FILE)
    bns.verbosity = 2
    bns.do_fix = True

    bns.check_attackers()
    for table in ["attacker", "session"]:
        bns.check_attempts_count(table)
        bns.check_attempts_dates(table)
    bns.check_geolocations()
    bns.database_optimize()
    bns.generate_targets()
    bns.generate_stats()
    bns.generate_minimaps()
    bns.generate_map_data()


def runtests_checker() -> bool:
    """Check that stat file is consistent."""
    with open(SCRUBBER_STATS_FILE) as f:
        d = json.load(f)
        d = d["data"][0]
        print(d)

        return d[0] > 10


def runtests_ssh() -> None:
    """Run both servers and run a few login/passwd attempts."""
    servers = []  # type: list[BlacknetServer]
    threads = []

    # Create master server instance
    print("[+] Creating main server instance")
    bn_main = BlacknetMasterServer(MASTER_CONFIG_FILE)
    servers.append(bn_main)

    # Create SSH sensor instance
    print("[+] Creating SSH server instance")
    bn_ssh = BlacknetSensor(cfg_file=HONEYPOT_CONFIG_FILE)
    servers.append(bn_ssh)

    # Check configuration reloading
    for s in servers:
        s.reload()

    # Prepare to serve requests in separate threads
    t = Thread(target=runtests_main_serve, args=(bn_main,))
    threads.append(t)

    t = Thread(target=runtests_ssh_serve, args=(bn_ssh,))
    threads.append(t)

    for t in threads:
        t.daemon = True
        t.start()

    print("[+] Running SSH login attempts")

    # Simulate a SSH client connecting
    runtests_ssh_client()

    # Close servers
    bn_ssh.shutdown()
    bn_main.shutdown()
    print("[+] Closed servers")


if __name__ == "__main__":
    # Log paramiko warnings to stdout.
    logger = logging.getLogger("paramiko")
    logger.setLevel(logging.WARNING)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    # Update geolocation database with minimal sample
    runtests_update()

    # Main SSH Test
    runtests_ssh()

    # DB scrubber and cache generator
    runtests_scrubber()

    # Check number of attempts from database
    success = runtests_checker()
    if success:
        sys.exit(os.EX_OK)
    sys.exit(os.EX_SOFTWARE)
