#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.siptshark import SipShark
from lib.params import get_tshark_args


def main():
    file, filter, rport, ofile, nocolor = get_tshark_args()

    s = SipShark()
    s.file = file
    s.filter = filter
    s.rport = rport
    s.ofile = ofile
    s.nocolor = nocolor

    s.start()


if __name__ == '__main__':
    main()
