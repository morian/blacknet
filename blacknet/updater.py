import csv
import os
import shutil
import sys
import tempfile
import urllib
import zipfile

from config import BlacknetConfig
from database import BlacknetDatabase

GEOLITE_CSV_URL="https://geolite.maxmind.com/download/geoip/database/GeoLiteCity_CSV/GeoLiteCity-latest.zip"


class BlacknetGeoUpdater(object):
    """ Blacknet geolocation database updater """


    def __init__(self, cfg_file=None):
        """ load configuration file and database parameters """
        config = BlacknetConfig()
        config.load(cfg_file)
        self.__database = BlacknetDatabase(config)
        self.__dirname = tempfile.mkdtemp()
        self.__config = config
        self.__filepath = {}


    def __del__(self):
        shutil.rmtree(self.__dirname)
        self.__dirname = None


    def log(self, message):
        sys.stdout.write("%s\n" % message)


    def fetch_zip(self):
        zipf = open("%s/geolitecity.zip" % self.__dirname, 'wb')
        res = urllib.urlopen(GEOLITE_CSV_URL)

        content = res.read()
        zipf.write(content)
        zipf.close()

        self.log("[+] Fetched zipfile successfully")


    def extract_zip(self):
        zip_dir = "%s/geolitecity/" % self.__dirname
        if not os.path.exists(zip_dir):
            os.mkdir(zip_dir)

        zip_ref = zipfile.ZipFile("%s/geolitecity.zip" % self.__dirname, 'r')
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
        self.log("[!] We *STRONGLY* suggest running \"blacknet-db-scrubber --full-check --fix\" to update gelocation positions.")
