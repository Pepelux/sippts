#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import pyshark
from .lib.functions import parse_digest, packet_addresses, pyshark_compat, open_log, close_capture
from .lib.color import Color
from .lib.logos import Logo


class SipDump:
    def __init__(self):
        self.file = ""
        self.ofile = ""

        self.c = Color()

    def start(self):
        pyshark_compat()

        logo = Logo("sipdump")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Input file: {self.c.GREEN}{self.file}")
        print(f"{self.c.BWHITE}[✓] Output file: {self.c.GREEN}{self.ofile}")
        print(self.c.WHITE)

        try:
            capture = pyshark.FileCapture(self.file, display_filter="sip")
        except Exception as error:
            print(f"{self.c.RED}Error reading file {self.file}: {error}")
            print(self.c.WHITE)
            return

        fw = open_log(self.ofile, "w")

        sipauth = []

        # tshark fails while reading, not while opening: a truncated or
        # unsupported capture raised in the middle of the loop and, from
        # sippts-gui, took the console down
        try:
            paquetes = list(capture)
        except Exception as error:
            print(f"{self.c.RED}Error reading file {self.file}: {error}")
            print(self.c.WHITE)
            close_capture(capture)
            fw.close()
            return

        for packet in paquetes:
            (ipsrc, ipdst) = packet_addresses(packet)

            if ipsrc == None:
                continue

            try:
                method = packet.sip.Method
            except:
                method = ""
            try:
                auth = packet.sip.auth
            except:
                auth = ""

            if method != "" and auth != "":
                headers_auth = parse_digest(auth)
                if headers_auth:
                    username = headers_auth["username"]
                    realm = headers_auth["realm"]
                    uri = headers_auth["uri"]
                    nonce = headers_auth["nonce"]
                    cnonce = headers_auth["cnonce"]
                    nc = headers_auth["nc"]
                    qop = headers_auth["qop"]
                    algorithm = headers_auth["algorithm"]
                    response = headers_auth["response"]

                    # File format:
                    # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response
                    authline = '%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s\n' % (
                        ipsrc,
                        ipdst,
                        username,
                        realm,
                        method,
                        uri,
                        nonce,
                        cnonce,
                        nc,
                        qop,
                        algorithm,
                        response,
                    )

                    if f"{username}#{uri}" not in sipauth:
                        sipauth.append(f"{username}#{uri}")

                        print(
                            f"{self.c.WHITE}[{self.c.BYELLOW}{ipsrc}{self.c.WHITE} => {self.c.BYELLOW}{ipdst}{self.c.WHITE}] User: {self.c.BGREEN}{username}{self.c.WHITE} - URI: {self.c.BCYAN}{uri}{self.c.WHITE} - Hash: {self.c.BRED}{response}{self.c.WHITE}"
                        )

                        fw.write(authline)

        close_capture(capture)

        print(self.c.WHITE)
        print("The found data has been saved")

        fw.close()
