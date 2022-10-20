#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from lib.params import get_sipfuzzer_args
from modules.sipfuzzer import SipFuzzer


def main():
    ip, port, proto, verbose, all, delay = get_sipfuzzer_args()

    s = SipFuzzer()
    s.ip = ip
    s.port = port
    s.proto = proto
    s.verbose = verbose
    s.all = all
    s.delay = delay

    s.start()


if __name__ == '__main__':
    main()
