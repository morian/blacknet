from __future__ import annotations

import os
from optparse import OptionParser
from signal import SIGHUP, SIGINT, SIGTERM, getsignal, signal
from types import FrameType

from .. import BlacknetMasterServer

running = True
update = False


def blacknet_quit(signal: int, frame: FrameType | None) -> None:
    """Exit this program in a clean way."""
    global running
    running = False


def blacknet_reload(signal: int, frame: FrameType | None) -> None:
    """Reload server configuration in a clean way."""
    global update
    update = True


def blacknet_write_pid(filename: str) -> None:
    """Write the daemon PID to the provided file."""
    with open(filename, "w") as fp:
        fp.write(str(os.getpid()))


def run_master() -> None:
    """Run the blacknet server console script."""
    global update
    parser = OptionParser()
    parser.add_option(
        "-p",
        "--pidfile",
        dest="pidfile",
        help="file to write pid to at startup",
        metavar="FILE",
    )
    parser.add_option(
        "-c", "--config", dest="config", help="configuration file to use", metavar="FILE"
    )

    options, arg = parser.parse_args()

    # save current signal handlers
    sigint_handler = getsignal(SIGINT)
    sigterm_handler = getsignal(SIGINT)

    # install our current signal handlers
    signal(SIGINT, blacknet_quit)
    signal(SIGTERM, blacknet_quit)
    signal(SIGHUP, blacknet_reload)

    bns = BlacknetMasterServer(options.config)

    # Write PID after initialization
    if options.pidfile:
        blacknet_write_pid(options.pidfile)

    while running:
        if update:
            bns.reload()
            update = False
        bns.serve()

    # restore signal handlers
    signal(SIGINT, sigint_handler)
    signal(SIGTERM, sigterm_handler)

    bns.shutdown()
