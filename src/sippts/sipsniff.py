#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"


import ipaddress
import sys
import pyshark
import signal
import os
import platform
import re
import socket
import threading
import time
from .lib.functions import parse_message, parse_digest, searchInterface, pyshark_compat, close_capture
from .lib.color import Color
from .lib.logos import Logo


class SipSniff:
    def __init__(self):
        self.nocolor = ""
        self.dev = ""
        self.ofile = ""
        self.rport = 0
        self.proto = "ALL"
        self.verbose = 0
        self.auth = 0

        self.run = True

        self.found = []
        self.line = ["-", "\\", "|", "/"]
        self.pos = 0
        self.quit = False

        self.c = Color()

    def sniff_port(self):
        """
        Port of the bpf filter: the one given with -r, or the usual one of the
        protocol. It used to be fixed to 5060/5061, so a PBX on another port
        was captured by nobody and nothing was reported.
        """
        try:
            port = int(self.rport)
        except (TypeError, ValueError):
            port = 0

        if port > 0:
            return port

        if self.proto == "TLS":
            return 5061

        return 5060

    def signal_handler(self, sig, frame):
        print(f"{self.c.BYELLOW}You pressed Ctrl+C!")
        print(f"{self.c.BWHITE}\nStopping sniffer ...")
        print(self.c.WHITE)

        self.stop()

    def stop(self):
        self.run = False
        sys.exit()

    def start(self):
        # -nocolor has to be applied before anything is printed, the logo
        # included, or those lines keep their escape codes
        try:
            self.nocolor = int(self.nocolor)
        except (TypeError, ValueError):
            self.nocolor = 0

        if self.nocolor == 1:
            self.c.ansy()

        pyshark_compat()

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.auth = int(self.auth)
        except:
            self.auth = 0

        if self.ofile and self.ofile != "":
            if not re.search(r".pcap$", self.ofile):
                self.ofile += ".pcap"

        current_user = os.popen("whoami").read()
        current_user = current_user.strip()
        ops = platform.system()

        if ops == "Linux" and current_user != "root":
            print(
                f"{self.c.WHITE}You must be {self.c.RED}root{self.c.WHITE} to use this module"
            )
            return

        logo = Logo("sipsniff", self.nocolor)
        logo.print()

        self.proto = self.proto.upper()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(f"{self.c.BYELLOW}\nPress Ctrl+C to stop")
        print(self.c.WHITE)

        # define capture object
        if self.dev == "":
            networkInterface = searchInterface()
        else:
            networkInterface = self.dev

        print(f"{self.c.BWHITE}[✓] Listening on: {self.c.GREEN}{networkInterface}")

        if self.proto == "ALL":
            print(f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}UDP, TCP, TLS")
        else:
            print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}{self.proto}")

        if self.proto != "ALL":
            print(f"{self.c.BWHITE}[✓] Port: {self.c.GREEN}{self.sniff_port()}")

        if self.ofile != "":
            print(
                f"{self.c.BWHITE}[✓] Save captured data in the file: {self.c.GREEN}{self.ofile}"
            )
        if self.auth == 1:
            print(
                f"{self.c.BWHITE}[✓] {self.c.GREEN}Capture only authentication digest"
            )
        print(self.c.WHITE)

        self.run = True

        threads = list()

        if self.ofile and self.ofile != "":
            t = threading.Thread(
                target=self.sniff, args=(networkInterface, self.ofile), daemon=True
            )
            threads.append(t)
            t.start()
            time.sleep(0.1)

        t = threading.Thread(
            target=self.sniff, args=(networkInterface, ""), daemon=True
        )
        threads.append(t)
        t.start()

        t.join()

    def sniff(self, networkInterface, file):
        if file != "":
            capture = pyshark.LiveCapture(interface=networkInterface, output_file=file)
        else:
            if self.proto == "UDP":
                capture = pyshark.LiveCapture(
                    interface=networkInterface,
                    bpf_filter="udp port %d" % self.sniff_port(),
                    include_raw=True,
                    use_json=True,
                )
            elif self.proto == "TCP":
                capture = pyshark.LiveCapture(
                    interface=networkInterface,
                    bpf_filter="tcp port %d" % self.sniff_port(),
                    include_raw=True,
                    use_json=True,
                )
            elif self.proto == "TLS":
                capture = pyshark.LiveCapture(
                    interface=networkInterface,
                    bpf_filter="tcp port %d" % self.sniff_port(),
                    include_raw=True,
                    use_json=True,
                )
            else:
                capture = pyshark.LiveCapture(
                    interface=networkInterface, include_raw=True, use_json=True
                )

        # for packet in capture.sniff_continuously(packet_count=100):
        for packet in capture.sniff_continuously():
            if self.run == False:
                try:
                    close_capture(capture)
                except:
                    pass
                return
            else:
                # adjusted output
                try:
                    if file == "":
                        # get packet content
                        protocol = packet.transport_layer  # protocol type
                        src_addr = packet.ip.src  # source address
                        src_port = packet[protocol].srcport  # source port
                        dst_addr = packet.ip.dst  # destination address
                        # destination port
                        dst_port = packet[protocol].dstport
                        try:
                            mac_addr = packet.eth.src  # MAC address
                        except:
                            mac_addr = ""

                        # TLS connection
                        if self.proto == "TLS" or self.proto == "ALL":
                            if src_port == "5061" or dst_port == "5061":
                                if self.auth == 0:
                                    print(
                                        f"{self.c.YELLOW}Found TLS connection {src_addr}:{src_port} => {dst_addr}:{dst_port}"
                                    )

                        try:
                            msg = packet[protocol].payload_raw[0]
                            bytes_object = bytes.fromhex(msg)
                            ascii_string = bytes_object.decode("ASCII")
                            headers = parse_message(ascii_string)

                            if headers:
                                headers_auth = None
                                ua = headers["ua"]
                                method = headers["method"]
                                sipuser = headers["sipuser"]
                                sipdomain = headers["sipdomain"]
                                if sipuser == "":
                                    sipuser = headers["fromuser"]

                                # Is a SIP message?
                                if method != "":
                                    if self.auth == 0:
                                        print(
                                            f"{self.c.WHITE}[{method}] {src_addr}:{src_port} => {dst_addr}:{dst_port} - {ua}"
                                        )

                                    # a name, not an address: reported without
                                    # asking the DNS, a passive sniffer must not
                                    # generate traffic about what it captures
                                    isname = False
                                    try:
                                        ipaddress.ip_address(sipdomain)
                                    except ValueError:
                                        isname = True

                                    if isname and sipdomain != "":
                                        print(
                                            f"{self.c.CYAN}Found Domain {sipdomain} for user {sipuser} connecting to {dst_addr}:{dst_port}"
                                        )

                                    auth = headers["auth"]

                                    if auth != "":
                                        headers_auth = parse_digest(auth)

                                        if headers_auth:
                                            print(f"{self.c.GREEN}Auth={auth}\n")

                                # Search in headers
                                headers = ascii_string.split("\r\n")
                                for header in headers:
                                    m = re.search(
                                        r"^Via:\s.*\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*",
                                        header,
                                    )
                                    if m:
                                        ipfound = "%s" % (m.group(1))
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header Via"
                                            )

                                    m = re.search(
                                        r"^Route:\s\<sip:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*",
                                        header,
                                    )
                                    if m:
                                        ipfound = "%s" % (m.group(1))
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header Route"
                                            )

                                    m = re.search(
                                        r"^Record-Route:\s\<sip:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*",
                                        header,
                                    )
                                    if m:
                                        ipfound = "%s" % (m.group(1))
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header Record-Route"
                                            )

                                    m = re.search(
                                        r"^From:\s\"*(.*)\"*\s*\<[sip|sips]+:(.*)\@(.*)>.*",
                                        header,
                                    )
                                    if m:
                                        username = "%s" % (m.group(1))
                                        userfound = "%s" % (m.group(2))
                                        ipfound = "%s" % (m.group(3))
                                        if not username:
                                            username = ""
                                        if (
                                            username == ""
                                            and headers_auth
                                            and headers_auth["username"] != ""
                                        ):
                                            username = headers_auth["username"]
                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header From"
                                            )

                                    m = re.search(
                                        r"^To:\s\"*(.*)\"*\s*\<[sip|sips]+:(.*)\@(.*)>.*",
                                        header,
                                    )

                                    if m:
                                        username = "%s" % (m.group(1))
                                        userfound = "%s" % (m.group(2))
                                        ipfound = "%s" % (m.group(3))
                                        if not username:
                                            username = ""
                                        if (
                                            username == ""
                                            and headers_auth
                                            and headers_auth["username"] != ""
                                        ):
                                            username = headers_auth["username"]

                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound IP {ipfound} in header To"
                                            )

                                    m = re.search(
                                        r"^Contact:.*\<sips?:([^@]*)\@([^>]*)>", header
                                    )
                                    if m:
                                        userfound = "%s" % (m.group(1))
                                        ipfound = "%s" % (m.group(2))

                                        m = re.search(r"(.*):([0-9]*)", ipfound)
                                        if m:
                                            ipfound = "%s" % (m.group(1))
                                            portfound = "%s" % (m.group(2))
                                        else:
                                            portfound = "5060"

                                        if self.verbose == 1:
                                            print(
                                                f"{self.c.WHITE}\tFound user {userfound} from IP {ipfound}:{portfound} to IP {dst_addr}:{dst_port} in header Contact"
                                            )

                        except:
                            # Non ASCII data
                            pass
                except pyshark.capture.capture.TSharkCrashException:
                    print("Capture has crashed")
                except AttributeError as e:
                    # ignore packets other than TCP, UDP and IPv4
                    pass
        close_capture(capture)
