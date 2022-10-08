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


class RTCPBleed:
    def __init__(self):
        self.ip = ''
        self.start_port = '10000'
        self.end_port = '20000'
        self.delay = '1'

        self.c = Color()

    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.delay = int(self.delay)

        logo = Logo('rtcpbleed')
        logo.print()

        print(self.c.BWHITE + '[✓] Target IP: ' +
              self.c.YELLOW + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Port range:' + self.c.YELLOW + ' %d' %
              self.start_port + self.c.WHITE + '-' + self.c.YELLOW + '%d' % self.end_port)
        print(self.c.BWHITE + '[✓] Delay between tries: ' +
              self.c.YELLOW + '%d microseconds' % self.delay)
        print(self.c.WHITE)

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(RED + 'Failed to create socket' + WHITE)
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        message = ('80000000')
        byte_array = bytearray.fromhex(message)
        port = self.start_port

        while True:
            try:
                host = (str(self.ip), port)

                print(self.c.YELLOW + '[+] Checking port: %d' % port, end="\r")

                # Send data
                sock.sendto(byte_array, host)
                time.sleep(self.delay/1000.0)

                try:
                    (msg, addr) = sock.recvfrom(4096)
                    (ipaddr, rport) = addr
                    size = len(msg)

                    if size >= 0:
                        print(self.c.WHITE + 'received %d bytes from target port %d' %
                              (size, rport))
                except:
                    # No data available
                    pass
            except KeyboardInterrupt:
                print(self.c.YELLOW + '\nYou pressed Ctrl+C!')
                exit()
            except:
                pass

            port += 2
            if port > self.end_port:
                port = self.start_port
