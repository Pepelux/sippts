#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.1.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from modules.sipsend import SipSend
from lib.params import get_sipsend_args


def main():
    ip, rport, proto, method, domain, contact_domain, from_name, from_user, from_domain, from_tag, to_name, to_user, to_domain, to_tag, user, pwd, digest, branch, callid, cseq, sdp, sdes, user_agent, nocolor = get_sipsend_args()

    s = SipSend()
    s.ip = ip
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
    s.digest = digest
    s.branch = branch
    s.callid = callid
    s.cseq = cseq
    s.sdp = sdp
    s.sdes = sdes
    s.nocolor = nocolor

    s.start()


if __name__ == '__main__':
    main()
