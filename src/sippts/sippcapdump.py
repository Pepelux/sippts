#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
import re
from .lib.functions import parse_digest
from .lib.color import Color
from .lib.logos import Logo


class SipPCAPDump:
    def __init__(self):
        self.file = ''
        self.ofile = ''

        self.c = Color()

    def start(self):
        tmpfile = 'sippcapdump.tmp'

        logo = Logo('sippcapdump')
        logo.print()

        print(self.c.BWHITE+'[✓] Input file: %s ...' % self.file)
        print(self.c.BWHITE+'[✓] Output file: %s ...\n' % self.ofile)
        print(self.c.WHITE)

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

                        print(self.c.WHITE + '[' + self.c.YELLOW + '%s' % ipsrc + self.c.WHITE + '->' + self.c.YELLOW + '%s' % ipdst + self.c.WHITE + '] ' +
                              self.c.GREEN + '%s' % username + self.c.WHITE + ':' + self.c.RED + '%s' % response)

                        fw.write(authline)

                line = f.readline()

            print(self.c.WHITE)
            print('The found data has been saved')

        f.close()
        fw.close()
        os.remove(tmpfile)
