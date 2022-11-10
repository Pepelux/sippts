#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
from lib.color import Color
from lib.logos import Logo

# https://www.wireshark.org/docs/dfref/s/sip.html


class SipShark:
    def __init__(self):
        self.file = ''
        self.ofile = ''
        self.rport = ''
        self.filter = 'None'

        self.cid = ''
        self.method = ''
        self.frame = ''
        self.rtp_extract = 'False'

        self.nocolor = ''
        self.c = Color()

    def start(self):
        if self.nocolor == 1:
            self.c.ansy()

        logo = Logo('siptshark')
        logo.print()

        if self.filter.lower()[0:6] == 'method':
            (self.filter, self.method) = self.filter.split(' ')
            self.method = self.method.upper()

        if self.filter.lower()[0:5] == 'frame':
            (self.filter, self.frame) = self.filter.split(' ')

        if self.filter.lower() != 'callids' and self.filter.lower()[0:6] == 'callid':
            (self.filter, self.cid) = self.filter.split(' ')

        if self.filter.lower() == 'stats':
            print(self.c.BYELLOW + 'Dialog statistics:' + self.c.WHITE)
            print(self.c.GREEN)
            os.system(
                "tshark -r %s -d udp.port==5060,sip -q -z sip,stat" % self.file)
            print(self.c.WHITE)

        if self.filter.lower() == 'messages':
            print(self.c.BYELLOW + 'SIP messages:' + self.c.WHITE)
            print(self.c.WHITE)
            os.system("tshark -r %s -Y sip" % self.file)
            print(self.c.GREEN)

        if self.filter.lower() == 'frames':
            print(self.c.BYELLOW + 'Frames:' + self.c.WHITE)
            print(self.c.WHITE)
            os.system(
                "tshark -r %s -Y sip -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % self.file)
            print(self.c.WHITE)

        if self.frame != '':
            os.system(
                "tshark -r %s -Y '(frame.number==%s)' -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % (self.file, self.frame))

        if self.method != '':
            os.system(
                "tshark -r %s -Y 'sip.CSeq.method eq %s'" % (self.file, self.method))

        if self.filter.lower() == 'callids':
            print(self.c.BYELLOW + 'Captured CallerID from dialogs:' + self.c.WHITE)
            print(self.c.WHITE)
            os.system(
                "tshark -r %s -T fields -e sip.Call-ID |sort |uniq" % self.file)
            print(self.c.WHITE)

        if self.cid != '':
            os.system(
                "tshark -r %s -Y 'sip.Call-ID eq \"%s\"' -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % (self.file, self.cid))

        if self.filter.lower() == 'rtp':
            print(self.c.BYELLOW + 'Captured RTP streams:' + self.c.WHITE)
            print(self.c.CYAN)
            os.system("tshark -r %s -q -z rtp,streams" % self.file)
            print(self.c.WHITE)

        if self.filter.lower() == 'auth':
            print(self.c.BYELLOW + 'Captured Authentication Digest:' + self.c.WHITE)
            print(self.c.GREEN)
            os.system(
                "tshark -r %s -Y sip -T fields -e sip.auth |grep username |sort |uniq |sed 's/\\\\r\\\\n/\\n/g'" % self.file)
            print(self.c.WHITE)

        if self.ofile != '' and self.rport != '':
            os.system("tshark -r %s -Y udp.port=='%s' -d udp.port=='%s,rtp' -T fields -e rtp.payload -w %s" %
                      (self.file, self.rport, self.rport, self.ofile))
            print('\nRTP stream has been saved info %s. You can use tools/pcap2wav.sh to try to convert it to a WAV file' % self.ofile)
