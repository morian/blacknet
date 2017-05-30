import csv
import os
import shutil
import sys
import tempfile
import urllib
import zipfile

from .config import BlacknetConfig, BlacknetConfigurationInterface
from .database import BlacknetDatabase

GEOLITE_CSV_URL="https://geolite.maxmind.com/download/geoip/database/GeoLiteCity_CSV/GeoLiteCity-latest.zip"


class BlacknetGeoUpdater(BlacknetConfigurationInterface):
    """ Blacknet geolocation database updater """


    def __init__(self, cfg_file=None):
        """ load configuration file and database parameters """
        config = BlacknetConfig()
        config.load(cfg_file)
        BlacknetConfigurationInterface.__init__(self, config, 'server')

        self.__database = BlacknetDatabase(config)
        self.__test_mode = None
        self.__dirname = None
        self.__config = config
        self.__filepath = {}


    def __del__(self):
        if not self.test_mode:
            dirname = self.dirname
        else:
            # That's the ZipDir (extracted)
            dirname = "%s/geolitecity" % self.dirname
        shutil.rmtree(dirname)
        self.__dirname = None


    @property
    def test_mode(self):
        if self.__test_mode is None:
            if self.has_config('test_mode'):
                self.__test_mode = bool(self.get_config('test_mode'))
            else:
                self.__test_mode = False
        return self.__test_mode


    @property
    def dirname(self):
        if self.__dirname is None:
            if self.test_mode:
                self.__dirname = 'tests/geo-updater/'
            else:
                self.__dirname = tempfile.mkdtemp()
        return self.__dirname

    def log(self, message):
        sys.stdout.write("%s\n" % message)


    def fetch_zip(self):
        if not self.test_mode:
            zipf = open("%s/geolitecity.zip" % self.dirname, 'wb')
            res = urllib.urlopen(GEOLITE_CSV_URL)

            content = res.read()
            zipf.write(content)
            zipf.close()

        self.log("[+] Fetched zipfile successfully")


    def extract_zip(self):
        zip_dir = "%s/geolitecity/" % self.dirname
        if not os.path.exists(zip_dir):
            os.mkdir(zip_dir)

        zip_ref = zipfile.ZipFile("%s/geolitecity.zip" % self.dirname, 'r')
        for item in zip_ref.namelist():
            filepath = zip_ref.extract(item, zip_dir)
            filename = os.path.basename(filepath)
            if filename == 'GeoLiteCity-Blocks.csv':
                self.__filepath['blocks'] = filepath
            elif filename == 'GeoLiteCity-Location.csv':
                self.__filepath['locations'] = filepath
            # Unknown file?

            self.log("[+] Extracted file %s" % item)
        zip_ref.close()


    def csv_blocks_import(self):
        block_file = self.__filepath['blocks']
        block_f = open(block_file, 'r')

        cursor = self.__database.cursor()
        cursor.truncate('blocks')

        self.log("[+] Trimmed blocks table")

        line_count = 0
        csv_data = csv.reader(block_f)
        for row in csv_data:
            line_count += 1
            if line_count < 3:
                continue
            row = [cell.decode('latin1') for cell in row]
            cursor.insert_block(row)
        block_f.close()

        self.log("[+] Updated blocks table (%u entries)" % (line_count - 2))


    def csv_locations_import(self):
        block_file = self.__filepath['locations']
        block_f = open(block_file, 'r')

        cursor = self.__database.cursor()
        cursor.truncate('locations')

        self.log("[+] Trimmed locations table")

        line_count = 0
        csv_data = csv.reader(block_f)
        for row in csv_data:
            line_count += 1
            if line_count < 3:
                continue
            row = [cell.decode('latin1') for cell in row]
            cursor.insert_location(row)
        block_f.close()

        self.log("[+] Updated locations table (%u entries)" % (line_count - 2))


    def csv_to_database(self):
        self.csv_blocks_import()
        self.csv_locations_import()


    def update(self):
        self.fetch_zip()
        self.extract_zip()
        self.csv_to_database()

        self.log("[+] Update Complete")
        if not self.test_mode:
            self.log("[!] We *STRONGLY* suggest running \"blacknet-db-scrubber --full-check --fix\" to update gelocation positions.")
