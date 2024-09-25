#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import websocket
import sys
import ssl
import rel
import time
from .lib.functions import create_message, get_free_port, get_machine_default_ip
from .lib.color import Color
from .lib.logos import Logo


class WsSend:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.rport = "5061"
        self.proto = "WS"
        self.method = "OPTIONS"
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.from_tag = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.to_tag = ""
        self.user_agent = "pplsip"
        self.verbose = "0"
        self.ppi = ""
        self.pai = ""
        self.localip = ""

        self.msg = ""
        self.c = Color()

    def start(self):
        supported_protos = ["UDP", "TCP", "TLS", "WS", "WSS"]
        supported_methods = [
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

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        # my IP address
        local_ip = self.localip
        if self.localip == "":
            try:
                local_ip = get_machine_default_ip()
            except:
                print(f"{self.c.BRED}Error getting local IP")
                print(
                    f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.cBWHITE} param"
                )
                print(self.c.WHITE)
                exit()

        try:
            local_ip = get_machine_default_ip()
        except:
            print(f"{self.c.BRED}Error getting local IP")
            print(
                f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.cBWHITE} param"
            )
            print(self.c.WHITE)
            exit()

        # check method
        if self.method not in supported_methods:
            print(f"{self.c.RED}Method {self.method} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.RED} + 'Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        logo = Logo("wssend")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Target: {self.c.GREEN}{self.ip}{self.c.WHITE}:{self.c.GREEN}{self.rport}{self.c.WHITE}/{self.c.GREEN}{self.proto}"
        )
        if (
            self.domain != ""
            and self.domain != str(self.ip)
            and self.domain != self.host
        ):
            print(f"{self.c.BWHITE}[✓] Customized Domain: {self.c.GREEN}{self.domain}")
        if self.contact_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized Contact Domain: {self.c.GREEN}{self.contact_domain}"
            )
        if self.from_name != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From Name: {self.c.GREEN}{self.from_name}"
            )
        if self.from_user != "100":
            print(
                f"{self.c.BWHITE}[✓] Customized From User: {self.c.GREEN}{self.from_user}"
            )
        if self.from_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From Domain: {self.c.GREEN}{self.from_domain}"
            )
        if self.from_tag != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From Tag: {self.c.GREEN}{self.from_tag}"
            )
        if self.to_name != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Name: {self.c.GREEN}{self.to_name}"
            )
        if self.to_user != "100":
            print(
                f"{self.c.BWHITE}[✓] Customized To User: {self.c.GREEN}{self.to_user}"
            )
        if self.to_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Domain: {self.c.GREEN}{self.to_domain}"
            )
        if self.to_tag != "":
            print(f"{self.c.BWHITE}[✓] Customized To Tag: {self.c.GREEN}{self.to_tag}")
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )
        print(self.c.WHITE)

        lport = get_free_port()

        if self.domain == "":
            self.domain = self.ip
        if not self.from_domain or self.from_domain == "":
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == "":
            self.to_domain = self.domain

        if self.contact_domain == "":
            self.contact_domain = local_ip

        self.msg = create_message(
            self.method,
            local_ip,
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
            self.from_tag,
            "1",
            self.to_tag,
            "",
            1,
            "",
            0,
            "",
            "",
            self.ppi,
            self.pai,
            "",
            1,
        )

        try:
            custom_protocol = "sip"
            protocol_str = "Sec-WebSocket-Protocol: " + custom_protocol

            c = self.get_ciphers()
            sslcipher = c[0]
        except:
            print(f"{self.c.RED}Socket error")
            print(self.c.WHITE)
            exit()

        print(self.c.WHITE)

        if self.verbose == 1:
            websocket.enableTrace(True)

        sslproto = ssl.PROTOCOL_TLS

        wss = websocket.WebSocketApp(
            "wss://%s:%s%s" % (self.ip, self.rport, self.path),
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header=[protocol_str],
        )

        wss.run_forever(
            sslopt={
                "check_hostname": False,
                "cert_reqs": ssl.CERT_NONE,
                "ssl_version": sslproto,
                "ciphers": sslcipher,
            }
        )

        rel.signal(2, rel.abort)  # Keyboard Interrupt
        rel.dispatch()

    def on_message(self, ws, message):
        if self.verbose == 1:
            print(self.c.WHITE)

        print(f"{self.c.YELLOW}{self.msg}{self.c.WHITE}")

        print(f"{self.c.GREEN}{message}{self.c.WHITE}")
        ws.close()
        sys.exit()

    def on_error(self, ws, error):
        print(error)

    def on_close(self, ws, a, b):
        print("### closed ###")
        ws.close()
        sys.exit()

    def on_open(self, ws):
        time.sleep(1)
        ws.send(self.msg)
        time.sleep(1)

    def get_ciphers(self):
        _DEFAULT_CIPHERS = (
            "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:"
            "DH+HIGH:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:ECDH+RC4:"
            "DH+RC4:RSA+RC4:!aNULL:!eNULL:!MD5"
        )

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
        context.set_ciphers(_DEFAULT_CIPHERS)
        context.load_default_certs()

        with socket.create_connection((self.ip, self.rport)) as sock:
            with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                return ssock.cipher()
