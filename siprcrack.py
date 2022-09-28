#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.siprcrack import SipRemoteCrack
from lib.params import get_sipremotecrack_args


def main():
    ip, host, rport, rexten, prefix, authuser, ext_len, proto, domain, contact_domain, user_agent, wordlist, nthreads, verbose, nocolor = get_sipremotecrack_args()

    s = SipRemoteCrack()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.domain = domain
    s.contact_domain = contact_domain
    s.exten = rexten
    s.prefix = prefix
    s.authuser = authuser
    s.ext_len = ext_len
    s.user_agent = user_agent
    s.threads = nthreads
    s.wordlist = wordlist
    s.verbose = verbose
    s.nocolor = nocolor

    s.start()


if __name__ == '__main__':
    main()
