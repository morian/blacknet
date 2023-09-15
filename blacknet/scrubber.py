import json
import os
import sys
import time
from urllib.request import urlretrieve

from .common import blacknet_gethostbyaddr, blacknet_int_to_ip
from .config import BlacknetConfig, BlacknetConfigurationInterface
from .database import BlacknetDatabase

WEEK_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


class BlacknetScrubber(BlacknetConfigurationInterface):
    """Blacknet database scrubber."""

    def __init__(self, cfg_file=None):
        """Instanciate a new blacknet scrubber to fix errors."""
        config = BlacknetConfig()
        config.load(cfg_file)
        super().__init__(config, "monitor")

        self.__database = BlacknetDatabase(config)
        self.__verbosity = 2
        self.__do_fix = False
        self.__cache_path = None
        self.__alive_delta = None
        self.__recent_delta = None
        self.__alive_threshold = None
        self.__recent_threshold = None
        self.__targets = []

    def log_error(self, message):
        """Log a new error to stderr."""
        if self.__verbosity > 0:
            sys.stderr.write("%s\n" % message)

    def log_action(self, message):
        """Log a new performed action to stdout."""
        suffix = " (DRY-RUN)" if not self.__do_fix else ""
        self.log_progress(f"{message}{suffix}")

    def log_progress(self, message):
        """Log progress to stdout (verbose)."""
        if self.__verbosity > 1:
            sys.stdout.write("%s\n" % message)

    @property
    def verbosity(self) -> int:
        """Get the current verbosity level."""
        return self.__verbosity

    @verbosity.setter
    def verbosity(self, level: int) -> None:
        """Set the current verbosity level."""
        self.__verbosity = level

    @property
    def do_fix(self) -> bool:
        """Tell whether we run in fix mode."""
        return self.__do_fix

    @do_fix.setter
    def do_fix(self, val) -> None:
        """Set whether we run in fix mode."""
        self.__do_fix = val

    def __timed_check(self, action, args, message):
        time_start = time.time()
        res = action(*args)
        time_diff = time.time() - time_start
        self.log_progress(f"[+] Checked {message} ({time_diff:.1f}s)")
        return res

    def __check_attackers(self):
        cursor = self.__database.cursor()
        for atk_id in cursor.missing_attackers():
            ip = blacknet_int_to_ip(atk_id)
            locid = cursor.get_locid(atk_id)
            if locid is None:
                self.log_error("[-] No match in geolocation database for IP %s." % ip)
                continue

            res = cursor.recompute_attacker_info(atk_id)
            if res is None:
                continue

            (first_seen, last_seen, count) = res
            dns = blacknet_gethostbyaddr(ip)
            self.log_action(f"[+] Fixing attacker {ip} ({dns})")

            if self.__do_fix:
                args = (atk_id, ip, dns, first_seen, last_seen, locid, count)
                cursor.insert_attacker(args)

    def check_attackers(self):
        """Check all attacker consistency."""
        self.__timed_check(self.__check_attackers, [], "missing attackers")

    def __check_attempts_count(self, target):
        """Checks for inconsistency and auto-repair."""
        cursor = self.__database.cursor()
        for t_id, current, computed in cursor.missing_attempts_count(target):
            self.log_action(
                f"[+] Fixing {target} with id {t_id} (from {current} to {computed})"
            )
            if self.__do_fix:
                cursor.update_attempts_count(target, t_id, computed)

    def check_attempts_count(self, target):
        """Check attempt counters consistencies."""
        message = "%s attempts counters" % target
        self.__timed_check(self.__check_attempts_count, [target], message)

    def __check_attempts_dates(self, target):
        cursor = self.__database.cursor()
        for data in cursor.missing_dates(target):
            (t_id, v_fs, v_ls, c_fs, c_ls) = data

            if v_fs != c_fs or v_ls != c_ls:
                self.log_action("[+] Fixing timestamps for %s with id %u" % (target, t_id))
                if self.__do_fix:
                    cursor.update_dates(target, t_id, c_fs, c_ls)

    def check_attempts_dates(self, target):
        """Check data consistency."""
        message = "%s dates consistency" % target
        self.__timed_check(self.__check_attempts_dates, [target], message)

    def __check_geolocations(self):
        cursor = self.__database.cursor()
        for atk_id, locid in cursor.get_attackers_location():
            nlocid = cursor.get_locid(atk_id)
            if nlocid != locid:
                ip = blacknet_int_to_ip(atk_id)
                self.log_action("[+] Fixing %s location from %u to %u" % (ip, locid, nlocid))
                if self.__do_fix:
                    cursor.update_attacker_location(atk_id, nlocid)

    def check_geolocations(self):
        """Check geolocation consistency."""
        self.__timed_check(self.__check_geolocations, [], "geolocation coherency")

    def __database_optimize(self, table):
        cursor = self.__database.cursor()
        cursor.optimize(table)

    def database_optimize(self):
        """Optimize the database."""
        if self.__do_fix:
            for table in ["attackers", "sessions", "blocks", "locations"]:
                self.__timed_check(self.__database_optimize, [table], f"{table} optimization")

    @property
    def cache_path(self) -> str:
        """Where the cache is located."""
        if not self.__cache_path:
            self.__cache_path = self.get_config("cache_path")
        return self.__cache_path

    @property
    def alive_delta(self):
        """For how many seconds we consider something alive."""
        if not self.__alive_delta:
            self.__alive_delta = int(self.get_config("alive_delta"))
        return self.__alive_delta

    @property
    def recent_delta(self):
        """For how many seconds we consider something recent."""
        if not self.__recent_delta:
            self.__recent_delta = int(self.get_config("recent_delta"))
        return self.__recent_delta

    @property
    def alive_threshold(self):
        """Get the alive threshold."""
        if not self.__alive_threshold:
            self.__alive_threshold = int(time.time() - 24 * 3600 * self.alive_delta)
        return self.__alive_threshold

    @property
    def recent_threshold(self):
        """Get the recent threshold."""
        if not self.__recent_threshold:
            self.__recent_threshold = int(time.time() - 24 * 3600 * self.recent_delta)
        return self.__recent_threshold

    def __timed_generation(self, action, filepath):
        time_start = time.time()
        res = action(filepath)
        time_diff = time.time() - time_start
        self.log_progress(f"[+] Generated file \'{filepath}\' ({time_diff:.1f}s)")
        return res

    def __json_export(self, filepath, data):
        path = os.path.join(self.cache_path, filepath)
        with open(path, "w") as f:
            f.write(json.dumps({"data": data}))

    def __generate_targets(self, filepath):
        cursor = self.__database.cursor()
        query = (
            "SELECT target, UNIX_TIMESTAMP(MAX(last_attempt)) > %s, "
            "UNIX_TIMESTAMP(MAX(last_attempt)) > %s "
            "FROM sessions GROUP BY target;"
        )
        res = cursor.execute(query, [self.recent_threshold, self.alive_threshold])
        if res:
            self.__targets = cursor.fetchall()
            self.__json_export(filepath, self.__targets)

    def generate_targets(self):
        """Generate the target report."""
        self.__timed_generation(self.__generate_targets, "targets.json")

    def __query_wrapper(self, query):
        cursor = self.__database.cursor()
        res = cursor.execute(query)
        if res:
            return cursor.fetchall()
        return None

    def __query_to_file(self, query, dest):
        """Get the result of query to JSON in file."""
        time_start = time.time()

        data = self.__query_wrapper(query)
        if data:
            self.__json_export(dest, data)

        time_diff = time.time() - time_start
        if data:
            self.log_progress(f"[+] JSON file {dest} generated ({time_diff:.1f}s).")
        else:
            self.log_progress(f"[-] No JSON data for file {dest} ({time_diff:.1f}s).")

    def generate_stats(self):
        """Generate the big statistics JSON file."""
        queries = {}
        queries["stats_logins"] = (
            "SELECT user, COUNT(*) "
            "FROM attempts "
            "GROUP BY user "
            "ORDER BY COUNT(*) DESC "
            "LIMIT 20;"
        )
        queries["stats_passwords"] = (
            "SELECT password, COUNT(*) "
            "FROM attempts "
            "GROUP BY password "
            "ORDER BY COUNT(*) DESC "
            "LIMIT 20;"
        )
        queries["stats_user_pass"] = (
            "SELECT user, password, COUNT(*) "
            "FROM attempts "
            "GROUP BY user,password "
            "ORDER BY COUNT(*) DESC "
            "LIMIT 20;"
        )
        queries["stats_general"] = (
            'SELECT (SELECT COUNT(*) FROM attempts), '
            '(SELECT COUNT(*) FROM attackers), '
            '(SELECT COUNT(*) FROM sessions), '
            '(SELECT COUNT(*) FROM attempts WHERE user = password), '
            '(SELECT COUNT(*) FROM attempts WHERE user = "root"), '
            '(SELECT COUNT(DISTINCT user) FROM attempts), '
            '(SELECT COUNT(DISTINCT password) FROM attempts), '
            '(SELECT COUNT(DISTINCT user, password) FROM attempts);'
        )
        queries["stats_countries"] = (
            "SELECT countries.country, CAST(SUM(n_attempts) AS UNSIGNED) AS c "
            "FROM attackers, locations, countries "
            "WHERE attackers.locId = locations.locId "
            "AND locations.country = countries.code "
            "GROUP BY countries.code "
            "ORDER BY c DESC "
            "LIMIT 10;"
        )

        # Only select recent targets.
        for target in [x[0] for x in self.__targets if (x[1] or self.__do_fix)]:
            filename = "stats_countries_%s" % target

            # Applying the filter this way is much faster.
            queries[filename] = (
                'SELECT countries.country, '
                'CAST(SUM(SES.n_attempts) AS UNSIGNED) AS c '
                'FROM ( '
                'SELECT attacker_id, n_attempts '
                'FROM sessions '
                'WHERE target = "%s" '
                ') as SES '
                'JOIN attackers ON SES.attacker_id = attackers.id '
                'JOIN locations ON attackers.locId = locations.locId '
                'JOIN countries ON locations.country = countries.code '
                'GROUP BY countries.code '
                'ORDER BY c DESC '
                'LIMIT 10;' % self.__database.escape_string(target)
            )

        queries["stats_breakin"] = (
            'SELECT countries.country, COUNT(*) '
            'FROM ( '
            'SELECT DISTINCT attacker_id '
            'FROM attempts '
            'WHERE success = 1 '
            'AND client NOT LIKE "%libssh%" '
            ') as ATT '
            'JOIN attackers ON ATT.attacker_id = attackers.id '
            'JOIN locations ON attackers.locId = locations.locId '
            'JOIN countries ON locations.country = countries.code '
            'GROUP BY countries.code '
            'ORDER BY COUNT(*) DESC '
            'LIMIT 10;'
        )

        for filename in queries:
            self.__query_to_file(queries[filename], filename + ".json")

        # Only select alive targets + a global one
        targets = [None] + [x[0] for x in self.__targets if (x[2] or self.__do_fix)]
        for target in targets:
            filename = "wdays_%s" % target if target else "wdays"
            where = "WHERE UNIX_TIMESTAMP(date) > %s " % self.recent_threshold
            if target is not None:
                where = f'{where}AND target = "{self.__database.escape_string(target)}" '

            # day of week.
            time_start = time.time()
            data = [0 for i in range(7)]
            query = (
                "SELECT WEEKDAY(date), COUNT(*) "
                "FROM attempts " + where + "GROUP BY WEEKDAY(date);"
            )

            res = self.__query_wrapper(query)
            if res:
                for i in res:
                    data[i[0]] += i[1]
                self.__bar_chart(data, filename, time_start, WEEK_DAYS)

            # hour of day.
            time_start = time.time()
            filename = "hours_%s" % target if target else "hours"
            data = [0 for i in range(24)]
            query = (
                "SELECT HOUR(date), COUNT(*) "
                "FROM attempts " + where + "GROUP BY HOUR(date);"
            )
            res = self.__query_wrapper(query)
            if res:
                for i in res:
                    data[i[0]] += i[1]
                self.__bar_chart(data, filename, time_start)

    def __bar_chart(self, data, name, time_start, label=None):
        """Generate bar charts from data."""
        max_val = max(data)

        # Can happen when a filter has been set on dates.
        if not max_val:
            self.log_progress("[?] No available data to generate graph %s" % name)
            return

        params = {}
        params["cht"] = "bvs"
        params["chs"] = "%sx350" % str(33 + len(data) * 28)
        params["chd"] = "t:" + ",".join([str(round(100 * i / max_val)) for i in data])
        params["chf"] = "b0,lg,0,FFE7C6,0,76A4FB,1"
        params["chxt"] = "x,y"
        if label is not None:
            params["chxl"] = "0:|" + "|".join(label)

        # Build URL parameters from params dictionary
        url = "http://chart.apis.google.com/chart?" + "&".join(
            ["{}={}".format(*i) for i in params.items()]
        )

        # Get and write the image.
        destination = os.path.join(self.cache_path, "status_%s.png" % name)
        urlretrieve(url, destination)

        time_diff = time.time() - time_start
        self.log_progress(f"[+] Bar char {name} generated ({time_diff:0.1f}s)")

    def __generate_minimap(self, target=None):
        """Generate the minimap for virtual machine target."""
        time_start = time.time()

        params = {}
        params["cht"] = "t"
        params["chs"] = "200x100"
        params["chtm"] = "world"
        params["chf"] = "bg,s,F2F2F2"
        params["chco"] = "FFFFFF,BBFFBB,FFCC00,FF0000"
        params["chld"] = ""

        if target is None:
            query = (
                "SELECT CAST(SUM(n_attempts) AS UNSIGNED) as C, country "
                "FROM attackers "
                "JOIN locations ON attackers.locId  = locations.locId "
                "GROUP BY country "
                "ORDER BY C DESC;"
            )
        else:
            query = (
                'SELECT CAST(SUM(SES.n_attempts) AS UNSIGNED) as C, country '
                'FROM ('
                '  SELECT n_attempts, attacker_id '
                '  FROM sessions '
                '  WHERE target = "%s"'
                ') as SES '
                'JOIN attackers ON SES.attacker_id  = attackers.id '
                'JOIN locations ON attackers.locId  = locations.locId '
                'GROUP BY country '
                'ORDER BY C DESC;' % self.__database.escape_string(target)
            )

        temp_cache = {}
        max_val = 0.0

        res = self.__query_wrapper(query)
        if res:
            for attempts, country in res:
                if max_val < attempts:
                    max_val = float(attempts)
                temp_cache[country] = attempts

        if not temp_cache:
            return False

        params["chld"] = "".join(temp_cache)
        chd_array = [str(round(100 * temp_cache[i] / max_val)) for i in temp_cache]
        params["chd"] = "t:" + ",".join(chd_array)

        # Build URL parameters from params dictionary
        url = "http://chart.apis.google.com/chart?" + "&".join(
            ["{}={}".format(*i) for i in params.items()]
        )

        if target:
            destination = os.path.join(self.cache_path, "minimap_%s.png" % target)
        else:
            destination = os.path.join(self.cache_path, "minimap.png")

        urlretrieve(url, destination)

        time_diff = time.time() - time_start
        if target:
            self.log_progress(f"[+] Minimap for {target} generated ({time_diff:.2f}s).")
        else:
            self.log_progress("[+] Global minimap generated (%.2fs)." % time_diff)
        return True

    def generate_minimaps(self):
        """Generate the minimap using google APIs."""
        self.__generate_minimap()
        for target in [x[0] for x in self.__targets if (x[2] or self.__do_fix)]:
            self.__generate_minimap(target)

    def __generate_map_data(self, target=None):
        self.__database.cursor()
        suffix = "_%s" % target if target else ""

        queries = {}
        if not target:
            queries["map_regions"] = (
                "SELECT countries.code, "
                "CAST(SUM(n_attempts) AS UNSIGNED), "
                "countries.country "
                "FROM attackers "
                "JOIN locations ON attackers.locId = locations.locId "
                "JOIN countries ON locations.country = countries.code "
                "GROUP BY code;"
            )
        else:
            queries["map_regions" + suffix] = (
                'SELECT countries.code, '
                'CAST(SUM(SES.n_attempts) AS UNSIGNED), '
                'countries.country '
                'FROM ('
                '  SELECT n_attempts, attacker_id '
                '  FROM sessions '
                '  WHERE target = "%s"'
                ') as SES '
                'JOIN attackers ON SES.attacker_id = attackers.id '
                'JOIN locations ON attackers.locId = locations.locId '
                'JOIN countries ON locations.country = countries.code '
                'GROUP BY code;' % self.__database.escape_string(target)
            )

        if not target:
            queries["map_markers"] = (
                "SELECT latitude, longitude, "
                "CAST(SUM(n_attempts) AS UNSIGNED) AS C, city "
                "FROM attackers "
                "JOIN locations ON attackers.locId = locations.locId "
                "GROUP BY locations.locId "
                "ORDER BY C DESC "
                "LIMIT 250;"
            )
        else:
            queries["map_markers" + suffix] = (
                'SELECT latitude, longitude, '
                'CAST(SUM(SES.n_attempts) AS UNSIGNED) AS C, city '
                'FROM ('
                '  SELECT n_attempts, attacker_id '
                '  FROM sessions '
                '  WHERE target = "%s"'
                ') as SES '
                'JOIN attackers ON SES.attacker_id = attackers.id '
                'JOIN locations ON attackers.locId = locations.locId '
                'GROUP BY locations.locId '
                'ORDER BY C DESC '
                'LIMIT 250;' % self.__database.escape_string(target)
            )

        for filepath in queries:
            self.__query_to_file(queries[filepath], filepath + ".json")

    def generate_map_data(self):
        """Generate full map data."""
        self.__generate_map_data()
        for target in [x[0] for x in self.__targets if (x[2] or self.__do_fix)]:
            self.__generate_map_data(target)
