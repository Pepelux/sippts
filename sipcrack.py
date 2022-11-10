#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipcrack import SipDigestCrack
from lib.params import get_sipcrack_args


def main():
    # Values
    file, verbose, wordlist, bruteforce, charset, max, min, prefix, suffix = get_sipcrack_args()

    s = SipDigestCrack()
    s.file = file
    s.verbose = verbose
    s.wordlist = wordlist
    s.bruteforce = bruteforce
    s.charset = charset
    s.max = max
    s.min = min
    s.prefix = prefix
    s.suffix = suffix

    s.start()


if __name__ == '__main__':
    main()
