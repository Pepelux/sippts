#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
import re
from lib.functions import parse_digest

BRED = '\033[1;31;40m'
RED = '\033[0;31;40m'
BRED_BLACK = '\033[1;30;41m'
RED_BLACK = '\033[0;30;41m'
BGREEN = '\033[1;32;40m'
GREEN = '\033[0;32;40m'
BGREEN_BLACK = '\033[1;30;42m'
GREEN_BLACK = '\033[0;30;42m'
BYELLOW = '\033[1;33;40m'
YELLOW = '\033[0;33;40m'
BBLUE = '\033[1;34;40m'
BLUE = '\033[0;34;40m'
BMAGENTA = '\033[1;35;40m'
MAGENTA = '\033[0;35;40m'
BCYAN = '\033[1;36;40m'
CYAN = '\033[0;36;40m'
BWHITE = '\033[1;37;40m'
WHITE = '\033[0;37;40m'


class SipDump:
    def __init__(self):
        self.file = ''
        self.ofile = ''

    def start(self):
        tmpfile = 'sipdump.tmp'

        print(BWHITE+'[!] Input file: %s ...' % self.file)
        print(BWHITE+'[!] Output file: %s ...\n' % self.ofile)
        print(WHITE)

        os.system(
            "tshark -r %s -Y sip -T fields -e ip.src -e ip.dst -e sip.Method -e sip.auth |grep username |sort |uniq |sed 's/\\\\r\\\\n/\\n/g' > %s" % (self.file, tmpfile))

        fw = open(self.ofile, 'w')

        with open(tmpfile) as f:
            line = f.readline()

            while line:
                line = line.replace('\n', '')

                m = re.search(
                    '([0-9|\.]*)[\s|\t]*([0-9|\.]*)[\s|\t]*([A-Z]+)[\s|\t]*(.*)', line)
                if m:
                    ipsrc = '%s' % (m.group(1))
                    ipdst = '%s' % (m.group(2))
                    method = '%s' % (m.group(3))
                    auth = '%s' % (m.group(4))

                    headers_auth = parse_digest(auth)
                    if headers_auth:

                        username = headers_auth['username']
                        realm = headers_auth['realm']
                        uri = headers_auth['uri']
                        nonce = headers_auth['nonce']
                        cnonce = headers_auth['cnonce']
                        nc = headers_auth['nc']
                        qop = headers_auth['qop']
                        algorithm = headers_auth['algorithm']
                        response = headers_auth['response']

                        # File format:
                        # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response
                        authline = '%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s\n' % (
                            ipsrc, ipdst, username, realm, method, uri, nonce, cnonce, nc, qop, algorithm, response)

                        print(WHITE + '[' + YELLOW + '%s' % ipsrc + WHITE + '->' + YELLOW + '%s' % ipdst + WHITE + '] ' +
                              GREEN + '%s' % username + WHITE + ':' + RED + '%s' % response)

                        fw.write(authline)

                line = f.readline()

            print(WHITE)
            print('The found data has been saved')

        f.close()
        fw.close()
        os.remove(tmpfile)
