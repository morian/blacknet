from optparse import OptionParser, Values

from .. import BlacknetScrubber


def scrubber_options_parse() -> tuple[Values, list[str]]:
    """Parse and get options from command line."""
    parser = OptionParser()
    parser.add_option(
        "-c", "--config", dest="config", help="configuration file to use", metavar="FILE"
    )
    parser.add_option(
        "-k",
        "--check",
        dest="check_level",
        action="store_const",
        const=1,
        help="perform a fast data coherency check",
        default=0,
    )
    parser.add_option(
        "-K",
        "--full-check",
        dest="check_level",
        action="store_const",
        const=2,
        help="perform an extensive data coherency check",
        default=0,
    )
    parser.add_option(
        "-f",
        "--fix",
        dest="fixing",
        action="store_true",
        help="apply database fixes during checks",
        default=False,
    )
    parser.add_option(
        "-g",
        "--generate",
        dest="generate",
        action="store_true",
        help="generate cached data for blacknet website",
        default=False,
    )
    parser.add_option(
        "-q",
        "--quiet",
        dest="verbose",
        default=True,
        help="only display errors",
        action="store_false",
    )
    return parser.parse_args()


def run_scrubber() -> None:
    """Run the scrubber console script."""
    options, arg = scrubber_options_parse()

    bns = BlacknetScrubber(options.config)
    bns.verbosity = 2 if options.verbose else 1
    bns.do_fix = options.fixing

    if options.check_level > 0:
        bns.check_attackers()
        for t in ["attacker", "session"]:
            bns.check_attempts_count(t)

    if options.check_level > 1:
        for t in ["attacker", "session"]:
            bns.check_attempts_dates(t)
        bns.check_geolocations()

    if options.fixing:
        bns.database_optimize()

    if options.generate:
        bns.generate_targets()
        bns.generate_stats()
        bns.generate_minimaps()
        bns.generate_map_data()
