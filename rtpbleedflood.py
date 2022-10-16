#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.rtpbleedflood import RTPBleedFlood
from lib.params import get_rtcbleed_flood_args


def main():
    ip, port, payload, verbose = get_rtcbleed_flood_args()

    s = RTPBleedFlood()
    s.ip = ip
    s.port = port
    s.payload = payload
    s.verbose = verbose

    s.start()


if __name__ == '__main__':
    main()
