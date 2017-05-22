"""
setup.py for Blacknet.


This file is part of Blacknet - a SSH Distributed Honeypot Solution
Released under the MIT License.
"""

import blacknet
import setuptools
from distutils.command.install import INSTALL_SCHEMES


setuptools.setup(
    name         = blacknet.version.name,
    version      = blacknet.version.version,
    description  = blacknet.version.description,
    license      = blacknet.version.license,
    author       = blacknet.version.author,
    author_email = blacknet.version.author_email,
    url          = blacknet.version.url,
    packages     = ["blacknet"],
    platforms    = ["any"],
    install_requires = ["msgpack-python", "MySQL-python", "paramiko"],
    scripts      = ["bin/blacknet-main-server", "bin/blacknet-ssh-server",
                    "bin/blacknet-geo-updater", "bin/blacknet-db-scrubber"],
    long_description =
"""
Blacknet is a SSH Honeypot server for logging and aggregating login attempts.
Multiple honeypot clients can connect securely to report their data.
""",
)
