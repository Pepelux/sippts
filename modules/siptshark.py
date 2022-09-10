#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os

# https://www.wireshark.org/docs/dfref/s/sip.html

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

    def start(self):
        if self.filter.lower()[0:6] == 'method':
            (self.filter, self.method) = self.filter.split(' ')
            self.method = self.method.upper()

        if self.filter.lower()[0:5] == 'frame':
            (self.filter, self.frame) = self.filter.split(' ')

        if self.filter.lower() != 'callids' and self.filter.lower()[0:6] == 'callid':
            (self.filter, self.cid) = self.filter.split(' ')

        if self.filter.lower() == 'stats':
            print(BYELLOW + 'Dialog statistics:' + WHITE)
            print(GREEN)
            os.system(
                "tshark -r %s -d udp.port==5060,sip -q -z sip,stat" % self.file)
            print(WHITE)

        if self.filter.lower() == 'messages':
            print(BYELLOW + 'SIP messages:' + WHITE)
            print(WHITE)
            os.system("tshark -r %s -Y sip" % self.file)
            print(GREEN)

        if self.filter.lower() == 'frames':
            print(BYELLOW + 'Frames:' + WHITE)
            print(WHITE)
            os.system(
                "tshark -r %s -Y sip -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % self.file)
            print(WHITE)

        if self.frame != '':
            os.system(
                "tshark -r %s -Y '(frame.number==%s)' -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % (self.file, self.frame))

        if self.method != '':
            os.system(
                "tshark -r %s -Y 'sip.CSeq.method eq %s'" % (self.file, self.method))

        if self.filter.lower() == 'callids':
            print(BYELLOW + 'Captured CallerID from dialogs:' + WHITE)
            print(WHITE)
            os.system(
                "tshark -r %s -T fields -e sip.Call-ID |sort |uniq" % self.file)
            print(WHITE)

        if self.cid != '':
            os.system(
                "tshark -r %s -Y 'sip.Call-ID eq \"%s\"' -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % (self.file, self.cid))

        if self.filter.lower() == 'rtp':
            print(BYELLOW + 'Captured RTP streams:' + WHITE)
            print(CYAN)
            os.system("tshark -r %s -q -z rtp,streams" % self.file)
            print(WHITE)

        if self.filter.lower() == 'auth':
            print(BYELLOW + 'Captured Authentication Digest:' + WHITE)
            print(GREEN)
            os.system(
                "tshark -r %s -Y sip -T fields -e sip.auth |grep username |sort |uniq |sed 's/\\\\r\\\\n/\\n/g'" % self.file)
            print(WHITE)

        if self.ofile != '' and self.rport != '':
            os.system("tshark -r %s -Y udp.port=='%s' -d udp.port=='%s,rtp' -T fields -e rtp.payload -w %s" %
                      (self.file, self.rport, self.rport, self.ofile))
            print('\nRTP stream has been saved info %s. You can use tools/pcap2wav.sh to try to convert it to a WAV file' % self.ofile)
