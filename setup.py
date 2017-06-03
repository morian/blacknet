#!/usr/bin/env python

import codecs
from setuptools import setup, find_packages

version_tuple = __import__('blacknet').VERSION

if version_tuple[3] is not None:
    version = "%d.%d.%d_%s" % version_tuple
else:
    version = "%d.%d.%d" % version_tuple[:3]

with codecs.open('./README.rst', 'r', 'utf-8') as f:
    readme = f.read()

setup(
    name             = 'BlackNet',
    version          = version,
    url              = 'http://github.com/morian/blacknet/',
    author           = 'Romain Bezut',
    author_email     = 'blacknet@xdec.net',
    description      = 'Multi-head SSH honeypot system',
    license          = 'MIT',
    long_description = readme,
    packages         = find_packages(),
    scripts          = ['bin/blacknet-main-server', 'bin/blacknet-ssh-server',
                        'bin/blacknet-geo-updater', 'bin/blacknet-db-scrubber'],
    install_requires = ['configparser', 'msgpack-python', 'PyMySQL', 'paramiko'],
    classifiers      =  [
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: Implementation :: CPython",
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.4',
    ],
)
