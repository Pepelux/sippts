#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.rtpbleedinject import RTPBleedInject
from lib.params import get_rtcbleed_inject_args


def main():
    ip, port, payload, file = get_rtcbleed_inject_args()

    s = RTPBleedInject()
    s.ip = ip
    s.port = port
    s.payload = payload
    s.file = file

    s.start()


if __name__ == '__main__':
    main()
