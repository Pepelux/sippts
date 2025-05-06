#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

# based in rtpnatscan: https://github.com/kapejod/rtpnatscan

import socket
import fcntl
import os
import sys
import time
from .lib.color import Color
from .lib.logos import Logo


class RTCPBleed:
    def __init__(self):
        self.ip = ""
        self.start_port = "10000"
        self.end_port = "20000"
        self.delay = "1"
        self.ofile = ""

        self.run = True

        self.c = Color()

    def stop(self):
        print(self.c.WHITE)
        self.run = False


    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.delay = int(self.delay)

        logo = Logo("rtcpbleed")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Target IP: {self.c.YELLOW}{self.ip}")
        print(
            f"{self.c.BWHITE}[✓] Port range: {self.c.YELLOW}{self.start_port}{self.c.WHITE}-{self.c.YELLOW}{self.end_port}"
        )
        print(
            f"{self.c.BWHITE}[✓] Delay between tries: {self.c.YELLOW}{self.delay} microseconds"
        )
        print(self.c.WHITE)

        if self.ofile != "":
            f = open(self.ofile, "a+")
            f.write(f"Target IP: {self.ip}\n")
            
        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(f"{self.c.RED}Failed to create socket")
            print(self.c.WHITE)
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        message = "80000000"
        byte_array = bytearray.fromhex(message)
        port = self.start_port

        # while True:
        while port < self.end_port + 2:
            if self.run == True:
                try:
                    host = (str(self.ip), port)

                    print(f"{self.c.YELLOW}[+] Checking port: {str(port)}", end="\r")

                    # Send data
                    sock.sendto(byte_array, host)
                    time.sleep(self.delay / 1000.0)

                    try:
                        (msg, addr) = sock.recvfrom(4096)

                        if addr[1] == port:
                            (ipaddr, rport) = host
                            size = len(msg)

                            if size >= 0:
                                print(
                                    f"\n{self.c.WHITE}received {str(size)} bytes from target port {str(rport)}"
                                )

                                if self.ofile != "":
                                    f.write(f"received {str(size)} bytes from target port {str(rport)}\n")
                    except:
                        # No data available
                        pass
                except KeyboardInterrupt:
                    print(f"{self.c.YELLOW}\nYou pressed Ctrl+C!")
                    print(self.c.WHITE)
                    self.run = False
                except:
                    pass

                port += 2
                if port > self.end_port:
                    port = self.start_port
            else:
                port = self.end_port + 2

        print(self.c.WHITE)

        if self.ofile != "":
            f.write("\n")
            f.close()
