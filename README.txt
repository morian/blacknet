############################
## BlackNet Project 2.0.1 ##
############################

BlackNet includes a low interaction SSH honeypot and a master server used to
gather all attempts and draw statistics and maps out of it while displaying
attacks live on a website.

  The initial project features a modified VirtualBox environment as a high
interaction honeypot, gathering commands and events such as password changes.
We then moved to supporting Kippo, a medium interaction SSH honeypot in Python.
Now we simply use a lightweight paramiko server as a low interaction honeypot
since there are no more plans and no more times to register commands and
events automatically.
Still, the underlying MySQL tables and some website features still pretend
this time is not over. It should not be that difficult to use blacknet-client
with Kippo or Cowrie.

	This project was initially conducted during our studies in 2010 and was
rewritten in 2017 to necessitate lower maintenance and installation efforts.


INSTALLATION:

Blacknet is provided in two main parts, a SSH Server and a Main Server.
The Main Server (blacknet-main-server) is where the database is located.
The SSH Server (blacknet-ssh-server) is just a honeypot instance communicating
with the main server.
Please consult --help from both commands and read blacknet.cfg.example carefully.

You need to generate SSL certificates in order to make blacknet work
correctly over network stacks. Please use easy-rsa or equivalent to generate
your own PKI and deliver certificates between your server and your honeypots.

	* Requirements
		- Python 2.7 (not tested yet in 3.x)
		- MsgPack for Python (used by both Servers)
		- MySQLdb for Python (for MainServer only)
		- Paramiko (for SSH Server)

	* Installation
		- From source with "pip install ."
		- From pip repository "pip install blacknet"
		- Take a copy of blacknet.cfg.example and make your own configuration in
		  /etc/blacknet/blacknet.cfg or ${HOME}/.blacknet/blacknet.cfg
		- Execute blacknet-install.sql in your database to create the database structures

		- You can update (and fill) the database with geolocation updates using
		  the command "blacknet-geo-updater".
		- You can also scrub your data to generate reports or perform metadata checks
		  using "blacknet-db-scrubber" (please consult --help for details)
		- Command "blacknet-db-scrubber" might be best run in a crontab (with --quiet)
		- You might want to filter out some specific users for some or all
		  honeypots. Please see blacklist.cfg.example and put it in an appropriate
		  directory.


LICENSE:

	- This tool is provided under the MIT license
	- If you like the legal stuff please enjoy reading LICENSE.txt


RELEASE NOTES:

  - See CHANGELOG.txt


CREDITS:

  - Romain Bezut (2010, 2017)
  - Vivien Bernet-Rollande (2010)


THANKS:

	- We would like to thank the UTC (Université de Technologie de Compiègne).
	  Our school brought us support and have made this project possible during
	  class. Special thanks go to Mr. Schön who supervised this project.
	- We would like to thank all our friends who helped finding issues and
	  review this project in its early versions.
	- The hackers and bots who contributed in spite of themselves to this project.


CONTACTS:

	- github.com/morian
	- twitter.com/morian42
	- blacknet@xdec.net
