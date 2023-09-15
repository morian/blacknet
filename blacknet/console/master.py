import os

from signal import signal, getsignal, SIGINT, SIGTERM, SIGHUP
from optparse import OptionParser
from blacknet.master import BlacknetMasterServer

running = True
update = False


def blacknet_quit(signal, frame):
    """ exit this program in a clean way """
    global running
    running = False


def blacknet_reload(signal, frame):
    """ reload server configuration in a clean way """
    global update
    update = True


def blacknet_write_pid(filename):
    with open(filename, 'w') as fp:
        fp.write(str(os.getpid()))


def run_master():
    parser = OptionParser()
    parser.add_option("-p", "--pidfile", dest="pidfile",
                      help="file to write pid to at startup", metavar="FILE")
    parser.add_option("-c", "--config", dest="config",
                      help="configuration file to use", metavar="FILE")

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
