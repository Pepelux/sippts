#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.wssend import WsSend
from lib.params import get_wssend_args


def main():
    ip, rport, path, verbose, proto, method, domain, contact_domain, from_name, from_user, from_domain, from_tag, to_name, to_user, to_tag, to_domain, user_agent = get_wssend_args()

    s = WsSend()
    s.ip = ip
    s.path = path
    s.rport = rport
    s.proto = proto
    s.method = method
    s.domain = domain
    s.contact_domain = contact_domain
    s.from_name = from_name
    s.from_domain = from_domain
    s.from_tag = from_tag
    s.to_name = to_name
    s.from_user = from_user
    s.to_user = to_user
    s.to_domain = to_domain
    s.to_tag = to_tag
    s.user_agent = user_agent
    s.verbose = verbose

    s.start()


if __name__ == '__main__':
    main()
