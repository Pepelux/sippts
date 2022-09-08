#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipscan import SipScan
from lib.params import get_sipscan_args


def main():
    ip, rport, proto, method, domain, contact_domain, from_name, from_user, from_domain, to_name, to_user, to_domain, user_agent, nthreads, verbose, ping, file = get_sipscan_args()

    s = SipScan()
    s.ip = ip
    s.rport = rport
    s.proto = proto
    s.method = method
    s.domain = domain
    s.contact_domain = contact_domain
    s.from_name = from_name
    s.to_name = to_name
    s.from_user = from_user
    s.from_domain = from_domain
    s.to_user = to_user
    s.to_domain = to_domain
    s.user_agent = user_agent
    s.threads = nthreads
    s.verbose = verbose
    s.ping = ping
    s.file = file

    s.start()


if __name__ == '__main__':
    main()
