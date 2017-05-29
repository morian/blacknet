BlackNet 2
==========

BlackNet is a low interaction SSH multi-head honeypot system with logging
capabilities.

You can use it to gather all SSH attempts performed on multiple IPv4 address
you own on the internet and draw and export statistics out of it.
A dedicated web interface allows live tracking of what happens on your
honeypots, which IP addresses are targeting you and from where.


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
Integration with [Cowrie](http://github.com/micheloosterhof/cowrie/) should not
be hard to extend BlackNet features and make it highly interactive again.

This project was initially conducted during our engineering studies in 2010.
It was rewritten in 2017 to lower maintenance and installation efforts and to
fit with modern python programming standards.


Requirements
------------

* Python 2.7 or 3.4 (only tested on these versions)
* MsgPack for Python (used by both Servers)
* PyMySQL (used by MainServer only)
* Paramiko (used by honeypots to serve SSH requests)


Installation
------------

Blacknet is provided in two main parts, a SSH Server and a Main Server.
The Main Server (blacknet-main-server) is where the database is located.
The SSH Server (blacknet-ssh-server) is just a honeypot instance communicating
with the main server.
Please read --help from both commands and read blacknet.cfg.example carefully.

You need to generate SSL certificates in order to make blacknet work
correctly over network stacks.
Please use [easy-rsa](https://github.com/OpenVPN/easy-rsa) or equivalent to
generate your own PKI and deliver certificates between your server and your
honeypots.

* From source with "pip install ."
* From pip repository "pip install blacknet"
* Take a copy of blacknet.cfg.example and make your own configuration in
  /etc/blacknet/blacknet.cfg or ${HOME}/.blacknet/blacknet.cfg
* Execute blacknet-install.sql in your database to create the database structures
* You can update (and fill) the database with geolocation updates using
  the command "blacknet-geo-updater".
* You can also scrub your data to generate reports or perform metadata checks
  using "blacknet-db-scrubber" (please consult --help for details)
* Command "blacknet-db-scrubber" might be best run in a crontab (with --quiet)
* You might want to filter out some specific users for some or all
  honeypots. Please see blacklist.cfg.example and put it in an appropriate
  directory.


License
-------

This tool is provided under the MIT license
Please see [LICENSE.md](LICENSE.md)


Credits
-------
* Romain Bezut (2010, 2017)
* Vivien Bernet-Rollande (2010)


Thanks
------

* We would like to thank the UTC (Université de Technologie de Compiègne).
  Our school brought us support and have made this project possible during
  class. Special thanks go to our teacher who supervised this project.
* We would like to thank all our friends who helped finding issues and
  review this project in its early versions.
* The hackers and bots who contributed in spite of themselves to this project.
