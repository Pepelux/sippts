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


class RTPBleed:
    def __init__(self):
        self.ip = ""
        self.start_port = "10000"
        self.end_port = "20000"
        self.loops = "4"
        self.payload = "0"
        self.delay = "50"
        self.ofile = ""
        
        self.run = True

        self.c = Color()

    def stop(self):
        print(self.c.WHITE)
        self.run = False

    def start(self):
        self.start_port = int(self.start_port)
        self.end_port = int(self.end_port)
        self.loops = int(self.loops)
        self.payload = int(self.payload)
        self.delay = int(self.delay)

        logo = Logo("rtpbleed")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Target IP: {self.c.YELLOW}{self.ip}")
        print(
            f"{self.c.BWHITE}[✓] Port range: {self.c.YELLOW}{self.start_port}{self.c.WHITE}-{self.c.YELLOW}{self.end_port}"
        )
        print(f"{self.c.BWHITE}[✓] Payload type: {self.c.YELLOW}{self.payload}")
        print(
            f"{self.c.BWHITE}[✓] Number of tries per port: {self.c.YELLOW}{self.loops}"
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

        port = self.start_port

        while port < self.end_port + 2:
            if self.run == True:
                try:
                    host = (str(self.ip), port)

                    loop = 0
                    
                    while loop < self.loops:
                        cloop = str(loop).zfill(4)
                        cpayload = "%s" % hex(0x80 | self.payload & 0x7F)[2:]
                        # byte[0] = 0x80 => RTP version 2
                        # byte[1] = 0x80+payload => Codec version (https://en.wikipedia.org/wiki/RTP_payload_formats)
                        # byte[2-3] = Sequence number
                        message = "80" + cpayload + cloop + "0000000000000000"
                        byte_array = bytearray.fromhex(message)

                        print(
                            f"{self.c.YELLOW}[+] Checking port: {str(port)} with payload type {str(self.payload)} (Seq number: {str(loop+1)})  ",
                            end="\r",
                        )

                        # Send data
                        sock.sendto(byte_array, host)
                        time.sleep((self.delay + loop) / 1000.0)

                        loop += 1

                        try:
                            (msg, addr) = sock.recvfrom(4096)

                            if addr[1] == port:
                                (ipaddr, rport) = host
                                size = len(msg)

                                if size >= 12:
                                    x = "%s%s" % (hex(msg[2])[2:], hex(msg[3])[2:])
                                    seq = int("0x%s" % x, base=16)
                                    x = "%s%s%s%s" % (
                                        hex(msg[4])[2:],
                                        hex(msg[5])[2:],
                                        hex(msg[6])[2:],
                                        hex(msg[7])[2:],
                                    )
                                    timestamp = int("0x%s" % x, base=16)
                                    ssrc = "%s%s%s%s" % (
                                        hex(msg[8])[2:],
                                        hex(msg[9])[2:],
                                        hex(msg[10])[2:],
                                        hex(msg[11])[2:],
                                    )

                                    print(
                                        f"\n{self.c.WHITE}received {str(size)} bytes from target port {str(rport)} - loop {str(loop)}"
                                    )
                                    print(
                                        f"{self.c.WHITE}    [-] SSRC: {ssrc} - Timestamp: {timestamp} - Seq number: {seq}"
                                    )
                                    if self.ofile != "":
                                        f.write(f"received {str(size)} bytes from target port {str(rport)} - loop {str(loop)} - SSRC: {ssrc} - Timestamp: {timestamp} - Seq number: {seq}\n")
                        except:
                            # No data available
                            continue
                except KeyboardInterrupt:
                    print(f"{self.c.YELLOW}\nYou pressed Ctrl+C!")
                    print(self.c.WHITE)
                    self.run = False
                except:
                    pass

                port += 2
            else:
                port = self.end_port + 2

        print(self.c.WHITE)

        if self.ofile != "":
            f.write("\n")
            f.close()
