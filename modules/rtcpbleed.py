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


class RTCPBleed:
    def __init__(self):
        self.ip = ''
        self.start_port = '10000'
        self.end_port = '20000'
        self.delay = '1'

    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.delay = int(self.delay)

        print(BWHITE + '[!] Target IP: ' + YELLOW + '%s' % self.ip)
        print(BWHITE + '[!] Port range:' + YELLOW + ' %d' %
              self.start_port + WHITE + '-' + YELLOW + '%d' % self.end_port)
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

        message = ('80000000')
        byte_array = bytearray.fromhex(message)
        port = self.start_port

        while True:
            try:
                host = (str(self.ip), port)

                print(YELLOW + '[+] Checking port: %d' % port, end="\r")

                # Send data
                sock.sendto(byte_array, host)
                time.sleep(self.delay/1000.0)

                try:
                    (msg, addr) = sock.recvfrom(4096)
                    (ipaddr, rport) = addr
                    size = len(msg)

                    if size >= 0:
                        print(WHITE + 'received %d bytes from target port %d' %
                              (size, rport))
                except:
                    # No data available
                    pass
            except KeyboardInterrupt:
                print(YELLOW + '\nYou pressed Ctrl+C!')
                exit()
            except:
                pass

            port += 2
            if port > self.end_port:
                port = self.start_port
