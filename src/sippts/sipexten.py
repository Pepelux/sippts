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
import re
import time

try:
    import cursor
except:
    pass

from .lib.functions import (
    open_log,
    create_message,
    close_sockets,
    parse_message,
    expand_targets,
    host_sort_key,
    bind_local_port,
    format_time,
    write_results,
    RESULT_FIELDS,
    read_targets_file,
)
from .lib.color import Color
from .lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipExten:
    def __init__(self):
        self.ojson = ""
        self.ocsv = ""
        self.ip = ""
        self.file = ""
        self.oefile = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.exten = "100-300"
        self.prefix = ""
        self.method = "REGISTER"
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.user_agent = "pplsip"
        self.threads = "500"
        self.verbose = 0
        self.nocolor = ""
        self.ofile = ""
        self.filter = ""
        self.timeout = 5

        self.totaltime = 0
        self.found = []
        self.line = ["-", "\\", "|", "/"]
        self.pos = 0
        self.quit = False
        self.errors = 0

        self.c = Color()

    def start(self):
        # from sippts-gui it arrives as text, and settimeout() then raised
        # TypeError inside a bare except: the module reported a socket error
        # that never happened
        try:
            self.timeout = int(self.timeout)
        except (TypeError, ValueError):
            self.timeout = 5

        max_values = 100000

        supported_protos = ["UDP", "TCP", "TLS"]
        supported_methods = ["OPTIONS", "REGISTER", "INVITE"]

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        if self.nocolor == 1:
            self.c.ansy()

        self.method = self.method.upper()
        self.proto = self.proto.upper()
        if self.method == "REGISTER":
            self.from_user = ""

        # check method
        if self.method not in supported_methods:
            print(f"{self.c.BRED}Method{self.method} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # check protocol
        if self.proto != "ALL" and self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # create a list of IP addresses
        names = []

        if self.file != "":
            # targets from a file, in the ip:port/proto that 'scan -ot' writes
            # and 'leak -f' already read. Networks and ranges are accepted too
            (targets, errors) = read_targets_file(self.file, self.rport, self.proto)

            for error in errors:
                print(f"{self.c.BRED}{error}")
                print(self.c.WHITE)

            if targets == []:
                print(f"{self.c.BRED}No target to scan in {self.file}")
                print(self.c.WHITE)
                sys.exit()

            ips = [t[0] for t in targets]
        else:
            try:
                (ips, names) = expand_targets(self.ip)
            except ValueError as error:
                print(f"{self.c.BRED}{error}")
                print(self.c.WHITE)
                sys.exit()

            if ips == []:
                print(f"{self.c.BRED}No target to scan in {self.ip}")
                print(self.c.WHITE)
                sys.exit()

            targets = [(ip, self.rport, self.proto) for ip in ips]

        # when the target is a single host name, keep the name as SIP domain
        # (for a network or a range each host uses its own address, see scan_host)
        if self.domain == "" and len(names) == 1 and len(ips) == 1:
            self.domain = names[0]

        # create a list of extens
        extens = []
        for p in self.exten.split(","):
            p = p.strip()
            m = re.fullmatch(r"([0-9]+)-([0-9]+)", p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2)) + 1):
                    extens.append(x)
            else:
                extens.append(p)

        # threads to use
        nthreads = int(self.threads)
        total = len(ips) * len(extens)
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        logo = Logo("sipexten", self.nocolor)
        logo.print()

        if self.file != "":
            print(f"{self.c.BWHITE}[✓] Targets file: {self.c.GREEN}{self.file}")
        else:
            print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{self.ip}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(f"{self.c.BWHITE}[✓] Port: {self.c.GREEN}{self.rport}")
        if self.prefix != "":
            print(f"{self.c.BWHITE}[✓] Users prefix: {self.c.GREEN}{self.prefix}")
        print(f"{self.c.BWHITE}[✓] Exten range: {self.c.GREEN}{self.exten}")
        print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}{self.proto.upper()}")
        print(f"{self.c.BWHITE}[✓] Method to scan: {self.c.GREEN}{self.method}")

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
        if self.from_user != "100" and self.from_user != "":
            print(
                f"{self.c.BWHITE}[✓] Customized From User: {self.c.GREEN}{self.from_user}"
            )
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )

        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}{str(nthreads)}")
        if self.filter != "":
            print(
                f"{self.c.BWHITE}[✓] Filter response by code: {self.c.GREEN}{self.filter}"
            )
        if self.ofile != "":
            print(
                f"{self.c.BWHITE}[✓] Saving logs info file: {self.c.GREEN}{self.ofile}"
            )
        print(self.c.WHITE)

        start = time.time()

        # one pass per (port, proto): the workers read self.rport and
        # self.proto many times, so they are only reassigned between passes,
        # with no threads alive
        grupos = dict()

        for (ip, port, proto) in targets:
            grupos.setdefault((port, proto), [])

            if ip not in grupos[(port, proto)]:
                grupos[(port, proto)].append(ip)

        for (port, proto), lista in grupos.items():
            if self.quit == True:
                break

            self.rport = port
            self.proto = proto

            self.run_pass(lista, extens, nthreads, max_values)

        end = time.time()
        self.totaltime = int(end - start)

        self.found.sort(key=host_sort_key)
        self.print()

    def run_pass(self, ips, extens, nthreads, max_values):
        total = len(ips) * len(extens)
        values = product(ips, extens)
        values2 = []
        count = 0

        for i, val in enumerate(values):
            if self.quit == False:
                if count < max_values:
                    values2.append(val)
                    count += 1

                if count == max_values or i + 1 == total:
                    try:
                        with ThreadPoolExecutor(max_workers=nthreads) as executor:
                            if self.quit == False:
                                try:
                                    cursor.show()
                                except: 
                                    pass
                                for i, val2 in enumerate(values2):
                                    val_ipaddr = val2[0]

                                    try:
                                        val_exten = int(val2[1])
                                    except:
                                        print(
                                            self.c.RED
                                            + "Extension must be numeric. Maybe you want to use a prefix (-pr)"
                                        )
                                        sys.exit()
                                    if val_exten != 0:
                                        to_user = "%s%s" % (self.prefix, val_exten)
                                    else:
                                        to_user = "%s" % self.prefix

                                    executor.submit(self.scan_host, val_ipaddr, to_user)
                    except KeyboardInterrupt:
                        print(f"{self.c.RED}\nYou pressed Ctrl+C!")
                        print(self.c.WHITE)
                        try:
                            cursor.show()
                        except: 
                            pass
                        self.quit = True

                    values2.clear()
                    count = 0

    def scan_host(self, ipaddr, to_user):
        if self.quit == False:
            try:
                cursor.hide()
            except: 
                pass
            print(
                f"{self.c.BYELLOW}[{self.line[self.pos]}] Enumerating {ipaddr}:{self.rport}/{self.proto} => Exten {to_user.ljust(100)}",
                end="\r",
            )

            self.pos += 1
            if self.pos > 3:
                self.pos = 0

            try:
                if self.proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(f"{self.c.RED}Failed to create socket")
                print(self.c.WHITE)
                sys.exit(1)

            sock_ssl = None
            bind = "0.0.0.0"
            lport = bind_local_port(sock, bind)

            if lport == 0:
                sock.close()

                if self.verbose == 2:
                    print(f"{self.c.RED}\nFailed to bind a local port{self.c.WHITE}")
                return

            if self.proxy == "":
                host = (str(ipaddr), int(self.rport))
            else:
                if self.proxy.find(":") > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(":")
                else:
                    proxy_ip = self.proxy
                    proxy_port = "5060"

                host = (str(proxy_ip), int(proxy_port))

            contact_domain = self.contact_domain
            if contact_domain == "":
                contact_domain = "10.0.0.1"

            domain = self.domain
            if domain == "":
                domain = ipaddr

            if self.proxy != "":
                self.route = "<sip:%s;lr>" % self.proxy

            if self.method == "REGISTER":
                self.from_user = to_user

            msg = create_message(
                self.method,
                "",
                contact_domain,
                self.from_user,
                "",
                domain,
                to_user,
                "",
                domain,
                self.proto,
                domain,
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

                if self.verbose == 2:
                    print(
                        f"{self.c.WHITE}[+] Sending to {ipaddr}:{self.rport}/{self.proto} ..."
                    )
                    print(f"{self.c.WHITE}{msg}")

                rescode = "100"
                tries = 0

                while rescode[:1] == "1" and tries < 10:
                    tries += 1

                    # receive temporary code
                    if self.proto == "TLS":
                        resp = sock_ssl.recv(4096)
                        (ipaddr, rport) = host
                    else:
                        (resp, addr) = sock.recvfrom(4096)
                        (ipaddr, rport) = host

                    headers = parse_message(resp.decode())

                    if headers and headers["response_code"] != "":
                        response = "%s %s" % (
                            headers["response_code"],
                            headers["response_text"],
                        )
                        rescode = headers["response_code"]

                        if self.verbose == 2:
                            print(
                                f"{self.c.BWHITE}[-] Receiving from {ipaddr}:{rport}/{self.proto} ..."
                            )
                            print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")
                    else:
                        # not a SIP response, stop waiting for a final code
                        break

                headers = parse_message(resp.decode())

                if headers and headers["response_code"] != "":
                    if headers["response_code"] != "404":
                        if self.filter == "" or self.filter == headers["response_code"]:
                            response = "%s %s" % (
                                headers["response_code"],
                                headers["response_text"],
                            )
                            line = "%s###%d###%s###%s###%s###%s" % (
                                ipaddr,
                                rport,
                                self.proto,
                                to_user,
                                response,
                                headers["ua"],
                            )
                            self.found.append(line)

                    if self.verbose == 1:
                        if self.filter == "" or self.filter == headers["response_code"]:
                            print(
                                f"{self.c.WHITE}[Exten {to_user}] Response <{headers['response_code']} {headers['response_text']}> from {ipaddr}:{rport}/{self.proto}"
                            )

                return headers
            except socket.timeout:
                pass
            except Exception as error:
                # counted, so a run that swallows errors says so at the end
                self.errors += 1

                if self.verbose == 2:
                    print(f"{self.c.RED}\n{error}{self.c.WHITE}")
            finally:
                close_sockets(sock, sock_ssl)
                try:
                    cursor.show()
                except: 
                    pass

    def print(self):
        iplen = len("IP address")
        polen = len("Port")
        prlen = len("Proto")
        exlen = len("Extension")
        relen = len("Response")
        ualen = len("User-Agent")

        for x in self.found:
            (ip, port, proto, exten, res, ua) = x.split("###")
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(exten) > exlen:
                exlen = len(exten)
            if len(res) > relen:
                relen = len(res)
            if len(ua) > ualen:
                ualen = len(ua)

        tlen = iplen + polen + prlen + exlen + relen + ualen + 17

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (exlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+"
        )

        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'Extension'.ljust(exlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} | {self.c.BWHITE}{'User-Agent'.ljust(ualen)}{self.c.WHITE} |"
        )

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (exlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+"
        )

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            if self.ofile != "":
                f = open_log(self.ofile)

            for x in self.found:
                (ip, port, proto, exten, res, ua) = x.split("###")

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BCYAN}{exten.ljust(exlen)}{self.c.WHITE} | {self.c.BRED}{res.ljust(relen)}{self.c.WHITE} | {self.c.BBLUE}{ua.ljust(ualen)}{self.c.WHITE} |"
                )

                if self.ofile != "":
                    f.write(
                        "%s:%s/%s => %s - %s (%s)\n" % (ip, port, proto, exten, res, ua)
                    )

            if self.ofile != "":
                f.close()

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (exlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+"
        )
        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)

        if self.errors > 0:
            print(
                f"{self.c.YELLOW}[!] {str(self.errors)} error(s) while scanning, hidden without {self.c.BYELLOW}-vv{self.c.WHITE}"
            )
            print(self.c.WHITE)
            self.errors = 0
        # extensions found, one per line, to feed 'rcrack -ef'
        if self.oefile != "" and len(self.found) > 0:
            extensiones = []

            for x in self.found:
                valores = x.split("###")

                if len(valores) > 3 and valores[3] not in extensiones:
                    extensiones.append(valores[3])

            extensiones.sort()

            try:
                with open(self.oefile, "w") as fe:
                    for e in extensiones:
                        fe.write(e + "\n")
            except OSError as error:
                print(f"{self.c.RED}Error writing {self.oefile} ({error})")
                print(self.c.WHITE)

        write_results(
            self.found,
            RESULT_FIELDS["exten"],
            "exten",
            jsonfile=self.ojson,
            csvfile=self.ocsv,
            meta={
                "target": self.ip if self.ip != "" else self.file,
                "port": self.rport,
                "proto": self.proto,
                "method": self.method,
                "extens": self.exten,
                "elapsed": self.totaltime,
            },
        )

