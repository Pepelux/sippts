#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipflood import SipFlood
from lib.params import get_sipflood_args


def main():
    ip, rport, proto, method, domain, contact_domain, from_name, from_user, to_name, to_user, digest, user_agent, verbose = get_sipflood_args()

    s = SipFlood()
    s.ip = ip
    s.rport = rport
    s.proto = proto
    s.method = method
    s.domain = domain
    s.contact_domain = contact_domain
    s.from_name = from_name
    s.to_name = to_name
    s.from_user = from_user
    s.to_user = to_user
    s.user_agent = user_agent
    s.digest = digest
    s.verbose = verbose

    s.start()


if __name__ == '__main__':
    main()
