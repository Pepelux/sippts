#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.rtcpbleed import RTCPBleed
from lib.params import get_rtcpbleed_args


def main():
    ip, start_port, end_port, delay = get_rtcpbleed_args()

    s = RTCPBleed()
    s.ip = ip
    s.start_port = start_port
    s.end_port = end_port
    s.delay = delay

    s.start()


if __name__ == '__main__':
    main()
