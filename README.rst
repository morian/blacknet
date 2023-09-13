
==========
Blacknet 2
==========

.. image:: https://travis-ci.org/morian/blacknet.svg?branch=master
  :target: https://travis-ci.org/morian/blacknet

.. image:: https://coveralls.io/repos/github/morian/blacknet/badge.svg?branch=master
  :target: https://coveralls.io/github/morian/blacknet?branch=master

.. image:: https://img.shields.io/badge/license-MIT-blue.svg
  :target: https://github.com/morian/blacknet/blob/master/LICENSE


What
----

Blacknet is a low interaction SSH multi-head honeypot system with logging
capabilities.

You can use it to gather all SSH attempts performed on multiple IPv4 address
you own on the internet and draw and export statistics out of it.
A dedicated web interface allows live tracking of what happens on your
honeypots, which IP addresses are targeting you and from where.


Requirements
------------
* Python dependencies:
	- CPython_ >= 3.8
	- MsgPack_ >= 1.0.0
	- PyMySQL_
	- Paramiko_

* MySQL Server:
	- MySQL_ (tested with only 5.2+)
	- MariaDB_

.. _CPython: https://www.python.org
.. _MsgPack: https://msgpack.org
.. _PyMySQL: https://github.com/PyMySQL/PyMySQL
.. _Paramiko: http://www.paramiko.org
.. _MySQL: http://www.mysql.com/
.. _MariaDB: https://mariadb.org/


Installation
------------
Blacknet provides two components, a SSH Server (sensor) and a master server.
The master server (blacknet-master) is where the database is located.
The SSH server (blacknet-sensor) is just a honeypot instance communicating with
the master server.
Please read --help from both commands and read blacknet.cfg.example carefully.

You need to generate SSL certificates in order to make blacknet work
correctly over network stacks (please see next section).

- Installation using ``pip``:
  $ pip install blacknet

- Take a copy of blacknet.cfg.example and make your own configuration in
  ``/etc/blacknet/`` or ``${HOME}/.blacknet/``

- Run `blacknet-install.sql`_ in your MySQL database.
- You can update (and fill) the database with geolocation updates using
  the command ``blacknet-updater``.
- You can also scrub your data to generate reports or perform metadata checks
  using ``blacknet-scrubber`` (please consult --help for details)
- Command ``blacknet-scrubber`` might be best run in a crontab (with --quiet)
- You might want to filter out some specific users for some or all honeypots.
  Please see blacklist.cfg.example and put it in an appropriate directory.

.. _`blacknet-install.sql`: https://github.com/morian/blacknet/blob/master/share/blacknet-install.sql


Create your SSL certificates
----------------------------
Please use EasyRSA_ or equivalent to generate your own PKI and deliver
certificates between your server and your honeypots.

.. _EasyRsa: https://github.com/OpenVPN/easy-rsa

.. code:: bash

  # First clone the easyrsa repository
  cd /tmp/
  git clone https://github.com/OpenVPN/easy-rsa.git

  # Then create a new Authority
  cd /tmp/easy-rsa/easyrsa3
  ./easyrsa init-pki

  # When asked provide a Common Name for your CA (eg: Blacknet CA)
  ./easyrsa build-ca nopass

  # Generate and sign a certificate for master server (here called maestro)
  ./easyrsa gen-req maestro nopass
  ./easyrsa sign server maestro

  # Same for sensors
  ./easyrsa gen-req honeypot_00 nopass
  ./easyrsa sign client honeypot_00

PEM file format used by Blacknet starts with the private key and then
concatenates with the certificate (example bellow).

.. code:: bash

  cat pki/private/maestro.key pki/issued/maestro.crt > maestro.pem


History
-------
The initial project featured a modified VirtualBox environment as a high
interaction honeypot, gathering commands and events such as password changes.
We then moved to supporting Kippo, a medium interaction SSH honeypot written
in Python. Today's  version uses a lightweight paramiko server as a
low-interaction honeypot since there are no more plans (and no more time) to
handle commands and events automatically
(there are many security concerns around doing high interaction automatically).
The underlying MySQL schemes still refers to commands or events but they are
mostly kept for backward compatibility reasons.

Integration with Cowrie_ should not be hard to extend Blacknet features and
make it highly interactive again.

This project was initially conducted during our engineering studies in 2010.
It was rewritten in 2017 to lower maintenance and installation efforts and to
fit with modern python programming standards.

.. _Cowrie: http://github.com/micheloosterhof/cowrie/


Credits
-------
- Romain Bezut (2010, 2017)
- Vivien Bernet-Rollande (2010)


Thanks
------
- We would like to thank the UTC_ (Université de Technologie de Compiègne).
  Our school brought us support and have made this project possible during
  class. Special thanks go to our teacher who supervised this project.
- We would like to thank all our friends who helped finding issues and
  review this project in its early versions.
- The hackers and bots who contributed in spite of themselves to this project.

.. _UTC: https://www.utc.fr
