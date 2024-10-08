#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ssl
from .lib.functions import (
    create_message,
    get_free_port,
    parse_message,
    parse_digest,
    generate_random_string,
    calculateHash,
    get_machine_default_ip,
)
from .lib.color import Color
from .lib.logos import Logo


class SipSend:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.template = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.lport = ""
        self.proto = "UDP"
        self.method = ""
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
        self.user = ""
        self.pwd = ""
        self.user_agent = "pplsip"
        self.digest = ""
        self.branch = ""
        self.callid = ""
        self.cseq = "1"
        self.sdp = 0
        self.sdes = 0
        self.localip = ""
        self.nocolor = ""
        self.ofile = ""
        self.ppi = ""
        self.pai = ""
        self.header = ""
        self.nocontact = 0
        self.timeout = 5
        self.verbose = 0

        self.withcontact = 1

        self.c = Color()

    def start(self):
        supported_protos = ["UDP", "TCP", "TLS"]
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

        try:
            self.nocontact == int(self.nocontact)
        except:
            self.nocontact = 0

        if self.nocontact == 1:
            self.withcontact = 0

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        # my IP address
        local_ip = self.localip
        if self.localip == "":
            try:
                local_ip = get_machine_default_ip()
                self.localip = local_ip
            except:
                print(f"{self.c.BRED}Error getting local IP")
                print(
                    f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.cBWHITE} param"
                )
                print(self.c.WHITE)
                exit()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == "TLS":
            self.rport = 5061

        # check method
        if self.method not in supported_methods:
            print(f"{self.c.BRED}Method {self.method} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        if self.method == "INVITE" and self.timeout == 5:
            self.timeout = 30

        try:
            if self.proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(f"{self.c.RED}Failed to create socket")
            print(self.c.WHITE)
            sys.exit(1)

        logo = Logo("sipsend")
        logo.print()

        print(
            f"{self.c.BWHITE}[✓] Target: {self.c.GREEN}{self.ip}{self.c.WHITE}:{self.c.GREEN}{self.rport}{self.c.WHITE}/{self.c.GREEN}{self.proto}"
        )
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN} {self.proxy}")
        if self.template != "":
            print(f"{self.c.BWHITE}[✓] Template: {self.c.GREEN}{self.template}")
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

        if self.ofile != "":
            fw = open(self.ofile, "w")

            fw.write("[✓] Target: %s:%s/%s\n" % (self.ip, self.rport, self.proto))
            if self.proxy != "":
                fw.write("[✓] Outbound Proxy: %s" % self.proxy)
            if self.template != "":
                fw.write("[✓] Template: %s" % self.template)
            if (
                self.domain != ""
                and self.domain != str(self.ip)
                and self.domain != self.host
            ):
                fw.write("[✓] Customized Domain: %s\n" % self.domain)
            if self.contact_domain != "":
                fw.write("[✓] Customized Contact Domain: %s\n" % self.contact_domain)
            if self.from_name != "":
                fw.write("[✓] Customized From Name: %s\n" % self.from_name)
            if self.from_user != "100":
                fw.write("[✓] Customized From User: %s\n" % self.from_user)
            if self.from_domain != "":
                fw.write("[✓] Customized From Domain: %s\n" % self.from_domain)
            if self.from_tag != "":
                fw.write("[✓] Customized From Tag: %s\n" % self.from_tag)
            if self.to_name != "":
                fw.write("[✓] Customized To Name: %s\n" % self.to_name)
            if self.to_user != "100":
                fw.write("[✓] Customized To User: %s\n" % self.to_user)
            if self.to_domain != "":
                fw.write("[✓] Customized To Domain: %s\n" % self.to_domain)
            if self.to_tag != "":
                fw.write("[✓] Customized To Tag: %s\n" % self.to_tag)
            if self.user_agent != "pplsip":
                fw.write("[✓] Customized User-Agent: %s\n" % self.user_agent)
            fw.write("\n")

        if self.branch == "":
            self.branch = generate_random_string(71, 71, "ascii")
        if self.callid == "":
            self.callid = generate_random_string(32, 32, "hex")
        if self.from_tag == "":
            self.from_tag = generate_random_string(8, 8, "hex")

        if self.nocolor == 1:
            self.c.ansy()

        if self.sdp == None:
            self.sdp = 0
        if self.sdes == 1:
            self.sdp = 2
        if self.cseq == None or self.cseq == "":
            self.cseq = "1"

        if self.user != "" and self.pwd != "" and self.from_user == "100":
            self.from_user = self.user

        bind = "0.0.0.0"

        if self.lport == "" or self.lport == None:
            lport = get_free_port()
        else:
            lport = self.lport

        try:
            sock.bind((bind, lport))
        except:
            lport = get_free_port()
            sock.bind((bind, lport))

        if self.proxy == "":
            host = (str(self.ip), int(self.rport))
        else:
            if self.proxy.find(":") > 0:
                (proxy_ip, proxy_port) = self.proxy.split(":")
            else:
                proxy_ip = self.proxy
                proxy_port = "5060"

            host = (str(proxy_ip), int(proxy_port))

        if self.host != "" and self.domain == "":
            self.domain = self.host
        if self.domain == "":
            self.domain = self.ip
        if not self.from_domain or self.from_domain == "":
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == "":
            self.to_domain = self.domain

        if self.contact_domain == "":
            self.contact_domain = local_ip

        if self.proxy != "":
            self.route = "<sip:%s;lr>" % self.proxy

        if self.template != "":
            msg = ""
            tf = open(self.template, "r")

            for line in tf:
                msg = msg + line.replace("\n", "\r\n")

            msg = msg + "\r\n"
        else:
            if self.method == "REGISTER":
                if self.to_user == "100" and self.from_user != "100":
                    self.to_user = self.from_user
                if self.to_user != "100" and self.from_user == "100":
                    self.from_user = self.to_user

            msg = create_message(
                self.method,
                self.localip,
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
                self.branch,
                self.callid,
                self.from_tag,
                self.cseq,
                self.to_tag,
                self.digest,
                1,
                "",
                self.sdp,
                "",
                self.route,
                self.ppi,
                self.pai,
                self.header,
                self.withcontact,
            )

        try:
            sock.settimeout(self.timeout)

            if self.proto == "TCP":
                sock.connect(host)

            if self.proto == "TLS":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.load_default_certs()

                sock_ssl = context.wrap_socket(sock, server_hostname=str(host[0]))
                sock_ssl.connect(host)
                sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
            else:
                sock.sendto(bytes(msg[:8192], "utf-8"), host)

            if self.verbose == 1:
                print(
                    f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                )
                print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")
            else:
                print(f"{self.c.BYELLOW}[=>] Request {self.method}")

            if self.ofile != "":
                fw.write(
                    "[+] Sending to %s:%s/%s ...\n" % (self.ip, self.rport, self.proto)
                )
                fw.write(msg + "\n")

            rescode = "100"

            while rescode[:1] == "1":
                # receive temporary code
                if self.proto == "TLS":
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    via = headers["via"]

                    response = "%s %s" % (
                        headers["response_code"],
                        headers["response_text"],
                    )
                    rescode = headers["response_code"]
                    if self.verbose == 1:
                        print(
                            f"{self.c.BWHITE}[-] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                        )
                        print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")
                    else:
                        print(f"{self.c.BGREEN}[<=] Response {response}")

                    if self.ofile != "":
                        fw.write(
                            "[-] Receiving from %s:%s/%s ...\n"
                            % (self.ip, self.rport, self.proto)
                        )
                        fw.write(resp.decode() + "\n")

                    totag = headers["totag"]

            if (
                self.user != ""
                and self.pwd != ""
                and (
                    headers["response_code"] == "401"
                    or headers["response_code"] == "407"
                )
            ):
                if headers["auth"] != "":
                    auth = headers["auth"]
                    auth_type = headers["auth-type"]
                    headers = parse_digest(auth)
                    realm = headers["realm"]
                    nonce = headers["nonce"]
                    uri = "sip:%s@%s" % (self.to_user, self.domain)
                    algorithm = headers["algorithm"]
                    cnonce = headers["cnonce"]
                    nc = headers["nc"]
                    qop = headers["qop"]

                    if qop != "" and cnonce == "":
                        cnonce = generate_random_string(8, 8, "ascii")
                    if qop != "" and nc == "":
                        nc = "00000001"

                    response = calculateHash(
                        self.user,
                        realm,
                        self.pwd,
                        self.method,
                        uri,
                        nonce,
                        algorithm,
                        cnonce,
                        nc,
                        qop,
                        0,
                        "",
                    )

                    digest = (
                        'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s'
                        % (self.user, realm, nonce, uri, response, algorithm)
                    )
                    if qop != "":
                        digest += ", qop=%s" % qop
                    if cnonce != "":
                        digest += ', cnonce="%s"' % cnonce
                    if nc != "":
                        digest += ", nc=%s" % nc

                    self.branch = generate_random_string(71, 71, "ascii")
                    self.cseq = str(int(self.cseq) + 1)

                    msg = create_message(
                        self.method,
                        self.localip,
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
                        self.branch,
                        self.callid,
                        self.from_tag,
                        self.cseq,
                        self.to_tag,
                        digest,
                        auth_type,
                        "",
                        self.sdp,
                        via,
                        self.route,
                        self.ppi,
                        self.pai,
                        self.header,
                        self.withcontact,
                    )

                    try:
                        if self.proto == "TLS":
                            sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                        else:
                            sock.sendto(bytes(msg[:8192], "utf-8"), host)

                        # Send AUTH
                        if self.verbose == 1:
                            print(
                                f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                            )
                            print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")
                        else:
                            print(f"{self.c.BYELLOW}[=>] Request {self.method} (AUTH)")

                        if self.ofile != "":
                            fw.write(
                                "[+] Sending to %s:%s/%s ...\n"
                                % (self.ip, self.rport, self.proto)
                            )
                            fw.write(msg + "\n")

                        rescode = "100"

                        while rescode[:1] == "1":
                            # receive temporary code
                            if self.proto == "TLS":
                                resp = sock_ssl.recv(4096)
                            else:
                                resp = sock.recv(4096)

                            headers = parse_message(resp.decode())

                            if headers and headers["response_code"] != "":
                                response = "%s %s" % (
                                    headers["response_code"],
                                    headers["response_text"],
                                )
                                rescode = headers["response_code"]
                                if self.verbose == 1:
                                    print(
                                        f"{self.c.BWHITE}[-] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                                    )
                                    print(
                                        f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}"
                                    )
                                else:
                                    print(f"{self.c.BGREEN}'[<=] Response {response}")

                                if self.ofile != "":
                                    fw.write(
                                        "[-] Receiving from %s:%s/%s ...\n"
                                        % (self.ip, self.rport, self.proto)
                                    )
                                    fw.write(resp.decode() + "\n")
                    except:
                        print(self.c.WHITE)

            # receive 200 Ok - call answered
            if headers["response_code"] == "200":
                totag = headers["totag"]

                # send ACK
                msg = create_message(
                    "ACK",
                    self.localip,
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
                    self.branch,
                    self.callid,
                    self.from_tag,
                    self.cseq,
                    totag,
                    "",
                    1,
                    "",
                    0,
                    via,
                    self.route,
                    "",
                    "",
                    self.header,
                    self.withcontact,
                )

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")
                else:
                    print(f"{self.c.BYELLOW}[=>] Request ACK")

                if self.ofile != "":
                    fw.write("[+] Request ACK\n")
                    fw.write(msg + "\n")

                if self.proto == "TLS":
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)

        except socket.timeout:
            pass
        except:
            print(f"{self.c.RED}[!] Socket connection error\n{self.c.WHITE}")
            pass
        finally:
            sock.close()

        if self.ofile != "":
            fw.close()
