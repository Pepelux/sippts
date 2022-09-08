#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.1.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipinvite import SipInvite
from lib.params import get_sipinvite_args


def main():
    ip, rport, proto, domain, contact_domain, from_name, from_user, from_domain, to_name, to_user, to_domain, transfer, auth_user, auth_pwd, user_agent, verbose = get_sipinvite_args()

    s = SipInvite()

    s.ip = ip
    s.rport = rport
    s.proto = proto
    s.domain = domain
    s.contact_domain = contact_domain
    s.from_name = from_name
    s.from_user = from_user
    s.from_domain = from_domain
    s.to_name = to_name
    s.to_user = to_user
    s.to_domain = to_domain
    s.transfer = transfer
    s.auth_user = auth_user
    s.auth_pwd = auth_pwd
    s.user_agent = user_agent
    s.verbose = verbose

    s.start()


if __name__ == '__main__':
    main()
