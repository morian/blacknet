from __future__ import annotations

import codecs
import csv
import os
import shutil
import sys
import tempfile
import zipfile
from codecs import StreamReaderWriter
from collections.abc import Iterator
from urllib.request import urlopen

from .config import BlacknetConfig, BlacknetConfigurationInterface
from .database import BlacknetDatabase

GEOLITE_CSV_URL = "https://geolite.maxmind.com/download/geoip/database/GeoLiteCity_CSV/GeoLiteCity-latest.zip"


def utf8_ensure(csv_file: StreamReaderWriter) -> Iterator[str]:
    """Ensure these lines are UTF-8."""
    for line in csv_file:
        # Those lines are 'unicode' in python2
        if not isinstance(line, str):
            line = line.strip().encode("utf-8")
        yield line


class BlacknetGeoUpdater(BlacknetConfigurationInterface):
    """Blacknet geolocation database updater."""

    def __init__(self, cfg_file: str | None = None):
        """Load configuration file and database parameters."""
        self.__dirname = None  # type: str | None
        self.__filepath = {}  # type: dict[str, str]
        self.__test_mode = None  # type: bool | None

        config = BlacknetConfig()
        config.load(cfg_file)
        self.__database = BlacknetDatabase(config)
        BlacknetConfigurationInterface.__init__(self, config, "server")

    def __del__(self) -> None:
        """Remove temporary directories upon deletion."""
        if not self.test_mode:  # pragma: no cover
            dirname = self.__dirname
        else:
            # That's the ZipDir (extracted)
            dirname = os.path.join(self.dirname, "geolitecity")

        if dirname:
            shutil.rmtree(dirname)
        self.__dirname = None

    @property
    def test_mode(self) -> bool:
        """Whether we are running in test mode."""
        if self.__test_mode is None:
            if self.has_config("test_mode"):
                self.__test_mode = bool(self.get_config("test_mode"))
            else:  # pragma: no cover
                self.__test_mode = False
        return self.__test_mode

    @property
    def dirname(self) -> str:
        """Current directory name (temporary)."""
        if self.__dirname is None:
            if self.test_mode:
                self.__dirname = os.path.join("tests", "geo-updater")
            else:
                self.__dirname = tempfile.mkdtemp()
        return self.__dirname

    def log(self, message: str) -> None:
        """Write something stdout."""
        sys.stdout.write("%s\n" % message)

    def fetch_zip(self) -> None:
        """Fetch the zip file on the internets."""
        if not self.test_mode:
            zip_file = os.path.join(self.dirname, "geolitecity.zip")
            zipf = open(zip_file, "wb")  # noqa: SIM115
            res = urlopen(GEOLITE_CSV_URL)  # noqa: S310

            content = res.read()
            zipf.write(content)
            zipf.close()

        self.log("[+] Fetched zipfile successfully")

    def extract_zip(self) -> None:
        """Extract the downloaded zip file."""
        zip_dir = os.path.join(self.dirname, "geolitecity")
        if not os.path.exists(zip_dir):
            os.mkdir(zip_dir)

        zip_file = os.path.join(self.dirname, "geolitecity.zip")
        zip_ref = zipfile.ZipFile(zip_file, "r")
        for item in zip_ref.namelist():
            filepath = zip_ref.extract(item, zip_dir)
            filename = os.path.basename(filepath)
            if filename == "GeoLiteCity-Blocks.csv":
                self.__filepath["blocks"] = filepath
            elif filename == "GeoLiteCity-Location.csv":
                self.__filepath["locations"] = filepath
            # Unknown file?

            self.log("[+] Extracted file %s" % item)
        zip_ref.close()

    def csv_blocks_import(self) -> None:
        """Import the new block table."""
        block_file = self.__filepath["blocks"]
        block_f = codecs.open(block_file, "r", "latin1")

        cursor = self.__database.cursor()
        cursor.truncate("blocks")

        self.log("[+] Trimmed blocks table")

        line_count = 0
        csv_data = csv.reader(utf8_ensure(block_f))
        for row in csv_data:
            line_count += 1
            if line_count < 3:
                continue
            cursor.insert_block(row)
        block_f.close()

        self.log("[+] Updated blocks table (%u entries)" % (line_count - 2))

    def csv_locations_import(self) -> None:
        """Import the new location table."""
        block_file = self.__filepath["locations"]
        block_f = codecs.open(block_file, "r", "latin1")

        cursor = self.__database.cursor()
        cursor.truncate("locations")

        self.log("[+] Trimmed locations table")

        line_count = 0
        csv_data = csv.reader(utf8_ensure(block_f))
        for row in csv_data:
            line_count += 1
            if line_count < 3:
                continue
            cursor.insert_location(row)
        block_f.close()

        self.log("[+] Updated locations table (%u entries)" % (line_count - 2))

    def csv_to_database(self) -> None:
        """Import CSV files to the database."""
        self.csv_blocks_import()
        self.csv_locations_import()

    def update(self) -> None:
        """Perform the whole update process."""
        self.fetch_zip()
        self.extract_zip()
        self.csv_to_database()

        self.log("[+] Update Complete")
        if not self.test_mode:  # pragma: no cover
            self.log(
                "[!] We *STRONGLY* suggest running "
                '"blacknet-scrubber --full-check --fix" to update gelocation positions.'
            )
