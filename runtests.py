#!/usr/bin/env python

from blacknet.scrubber import BlacknetScrubber
from blacknet.ssh_server import BlacknetSSHServer
from blacknet.main_server import BlacknetMainServer
from blacknet.updater import BlacknetGeoUpdater


if __name__ == '__main__':
    scrubber = BlacknetScrubber()
    updater = BlacknetGeoUpdater()
    mserv = BlacknetMainServer()

