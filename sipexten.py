#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.1.1'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipexten import SipExten
from lib.params import get_sipexten_args


def main():
    ip, host, rport, rexten, prefix, proto, method, domain, contact_domain, from_user, user_agent, nthreads, verbose, nocolor = get_sipexten_args()

    s = SipExten()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.method = method
    s.domain = domain
    s.contact_domain = contact_domain
    s.exten = rexten
    s.prefix = prefix
    s.from_user = from_user
    s.user_agent = user_agent
    s.threads = nthreads
    s.verbose = verbose
    s.nocolor = nocolor

    s.start()


if __name__ == '__main__':
    main()
