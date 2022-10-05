#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipping import SipPing
from lib.params import get_sipping_args


def main():
    ip, host, rport, proto, method, domain, contact_domain, from_name, from_user, from_domain, from_tag, to_name, to_user, to_domain, to_tag, user, pwd, digest, branch, callid, cseq, user_agent, localip, number = get_sipping_args()

    s = SipPing()
    s.ip = ip
    s.host = host
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
    s.user = user
    s.pwd = pwd
    s.user_agent = user_agent
    s.localip = localip
    s.digest = digest
    s.branch = branch
    s.callid = callid
    s.cseq = cseq
    s.number = number

    s.start()


if __name__ == '__main__':
    main()
