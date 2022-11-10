#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from sys import setdlopenflags
from modules.sipdigestleak import SipDigestLeak
from lib.params import get_sipdigestleak_args


def main():
    ip, host, proxy, rport, proto, domain, contact_domain, from_name, from_user, from_domain, to_name, to_user, to_domain, user_agent, localip, ofile, lfile, user, pwd, auth, verbose, sdp, sdes, file, ping = get_sipdigestleak_args()

    s = SipDigestLeak()
    s.ip = ip
    s.host = host
    s.proxy = proxy
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
    s.user_agent = user_agent
    s.ofile = ofile
    s.lfile = lfile
    s.localip = localip
    s.user = user
    s.pwd = pwd
    s.auth_code = auth
    s.verbose = verbose
    s.sdp = sdp
    s.sdes = sdes
    s.file = file
    s.ping = ping

    s.start()


if __name__ == '__main__':
    main()
