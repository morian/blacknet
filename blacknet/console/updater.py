from optparse import OptionParser

from ..updater import BlacknetGeoUpdater


def run_updater() -> None:
    """Run the updater console script."""
    parser = OptionParser()
    parser.add_option(
        "-c", "--config", dest="config", help="configuration file to use", metavar="FILE"
    )

    options, arg = parser.parse_args()

    updater = BlacknetGeoUpdater(options.config)
    updater.update()
