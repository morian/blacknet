from optparse import OptionParser
from blacknet.updater import BlacknetGeoUpdater


def run_updater():
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config",
                      help="configuration file to use", metavar="FILE")

    options, arg = parser.parse_args()

    updater = BlacknetGeoUpdater(options.config)
    updater.update()
