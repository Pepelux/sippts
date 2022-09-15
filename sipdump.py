#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.1.1'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipdump import SipDump
from lib.params import get_sipdump_args


def main():
    file, ofile = get_sipdump_args()

    s = SipDump()
    s.file = file
    s.ofile = ofile

    s.start()


if __name__ == '__main__':
    main()
