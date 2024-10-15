#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import random
import socket
import sys
import ipaddress
import ssl
import re
import time
from IPy import IP

try:
    import cursor
except:
    pass

from .lib.functions import (
    create_message,
    parse_message,
    get_machine_default_ip,
    ip2long,
    long2ip,
    get_free_port,
    ping,
    fingerprinting,
    format_time,
    load_cve,
    check_model,
)
from .lib.color import Color
from .lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor
import resource as res

class SipScan:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.proxy = ""
        self.route = ""
        self.rport = "5060"
        self.proto = "UDP"
        self.method = "OPTIONS"
        self.domain = ""
        self.contact_domain = ""
        self.from_user = "100"
        self.from_name = ""
        self.from_domain = ""
        self.to_user = "100"
        self.to_name = ""
        self.to_domain = ""
        self.user_agent = "pplsip"
        self.threads = 200
        self.verbose = 0
        self.ping = 0
        self.file = ""
        self.nocolor = ""
        self.ofile = ""
        self.oifile = ""
        self.fp = 0
        self.random = 0
        self.ppi = ""
        self.pai = ""
        self.localip = ""
        self.getcve = 0
        self.timeout = 5

        self.found = []
        self.ipsfound = []
        self.line = ["-", "\\", "|", "/"]
        self.pos = 0
        self.quit = False
        self.totaltime = 0
        self.fail = 0
        self.cvelist = []
        self.cve = []

        self.c = Color()
        

    def stop(self):
        try:
            cursor.show()
        except:
            pass
        print(self.c.WHITE)
        self.quit = True


    def set_ulimit(self, threads):
        # Get current 'ulimit -n' value
        soft,ohard = res.getrlimit(res.RLIMIT_NOFILE)
        hard = ohard
        
        # If ulimit < threads, set new value
        if soft < int(threads):
            soft = threads + 100

        if hard < soft:
            hard = soft

        try:
            res.setrlimit(res.RLIMIT_NOFILE,(soft,hard))
        except (ValueError,res.error):
            try:
                hard = soft
                # Trouble with max limit, retrying with soft,hard
                res.setrlimit(res.RLIMIT_NOFILE,(soft,hard))
            except Exception:
                # Failed to set ulimit, setting new threads value
                soft,hard = res.getrlimit(res.RLIMIT_NOFILE)
                self.threads = soft

        soft,hard = res.getrlimit(res.RLIMIT_NOFILE)


    def start(self):
        self.threads = int(self.threads)
        self.set_ulimit(self.threads)
    
        supported_protos = ["UDP", "TCP", "TLS"]
        supported_methods = ["OPTIONS", "REGISTER", "INVITE"]

        if self.nocolor == 1:
            self.c.ansy()

        self.method = self.method.upper()
        self.proto = self.proto.upper()
        if self.proto == "UDP|TCP|TLS":
            self.proto = "ALL"

        try:
            self.verbose == int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.ping == int(self.ping)
        except:
            self.ping = 0

        try:
            self.fp == int(self.fp)
        except:
            self.fp = 0

        try:
            self.random == int(self.random)
        except:
            self.random = 0

        try:
            self.getcve == int(self.getcve)
        except:
            self.getcve = 0

        # check method
        if self.method not in supported_methods:
            print(f"{self.c.BRED}Method {self.method} is not supported")
            print(self.c.WHITE)
            sys.exit()

        # check protocol
        if self.proto != "ALL" and self.proto not in supported_protos:
            print(f"{self.c.BRED}Protocol {self.proto} is not supported")
            print(self.c.WHITE)
            sys.exit()

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

        if self.rport.upper() == "ALL":
            self.rport = "1-65536"

        logo = Logo("sipscan")
        logo.print()

        # create a list of protocols
        protos = []
        if self.proto == "UDP" or self.proto == "ALL":
            protos.append("UDP")
        if self.proto == "TCP" or self.proto == "ALL":
            protos.append("TCP")
        if self.proto == "TLS" or self.proto == "ALL":
            protos.append("TLS")

        # create a list of ports
        ports = []
        for p in self.rport.split(","):
            m = re.search(r"([0-9]+)-([0-9]+)", p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2)) + 1):
                    ports.append(x)
            else:
                ports.append(p)

        # load cve file
        self.cvelist = load_cve()

        # create a list of IP addresses
        if self.file != "":
            try:
                with open(self.file) as f:
                    line = f.readline()

                    while line:
                        error = 0
                        line = line.replace("\n", "")

                        try:
                            if self.quit == False:
                                try:
                                    ip = socket.gethostbyname(line)
                                    self.ip = IP(ip, make_net=True)
                                except:
                                    try:
                                        self.ip = IP(line, make_net=True)

                                    except:
                                        if line.find("-") > 0:
                                            val = line.split("-")
                                            start_ip = val[0]
                                            end_ip = val[1]
                                            self.ip = line

                                            error = 1

                                ips = []

                                if error == 0:
                                    hosts = list(
                                        ipaddress.ip_network(str(self.ip)).hosts()
                                    )

                                    if hosts == []:
                                        hosts.append(self.ip)

                                    last = len(hosts) - 1
                                    start_ip = hosts[0]
                                    end_ip = hosts[last]

                                ipini = int(ip2long(str(start_ip)))
                                ipend = int(ip2long(str(end_ip)))

                                for i in range(ipini, ipend + 1):
                                    if (
                                        i != self.localip
                                        and long2ip(i)[-2:] != ".0"
                                        and long2ip(i)[-4:] != ".255"
                                    ):
                                        if self.ping == 0:
                                            ips.append(long2ip(i))
                                        else:
                                            print(
                                                f"{self.c.YELLOW}[+] Ping {str(long2ip(i))} ...{self.c.WHITE}",
                                                end="\r",
                                            )

                                            if ping(long2ip(i), "0.1") == True:
                                                print(
                                                    f"{self.c.GREEN}\n   [-] ... Pong {str(long2ip(i))}{self.c.WHITE}"
                                                )
                                                ips.append(long2ip(i))

                                self.prepare_scan(ips, ports, protos, self.ip)
                        except:
                            pass

                        line = f.readline()

                f.close()
            except:
                print(f"{self.c.RED}Error reading file {self.file}")
                print(self.c.WHITE)
                exit()
        else:
            ips = []
            
            for i in self.ip.split(","):
                hosts = []
                error = 0

                try:
                    if i.find("/") < 1:
                        i = socket.gethostbyname(i)
                        i = IP(i, make_net=True)
                    else:
                        i = IP(i, make_net=True)
                except:
                    if i.find("-") > 0:
                        val = i.split("-")
                        start_ip = val[0]
                        end_ip = val[1]

                        error = 1
                try:
                    if error == 0:
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
                    iplist = i

                    for i in range(ipini, ipend + 1):
                        if (
                            i != self.localip
                            and long2ip(i)[-2:] != ".0"
                            and long2ip(i)[-4:] != ".255"
                        ):
                            if self.ping == 0:
                                ips.append(long2ip(i))
                            else:
                                print(
                                    f"{self.c.YELLOW}[+] Ping {str(long2ip(i))} ...{self.c.WHITE}",
                                    end="\r",
                                )

                                if ping(long2ip(i), "0.1") == True:
                                    print(
                                        f"{self.c.GREEN}\n   [-] ... Pong {str(long2ip(i))}{self.c.WHITE}"
                                    )
                                    ips.append(long2ip(i))
                except:
                    if ips == []:
                        ips.append(self.ip)
                        iplist = self.ip

            self.prepare_scan(ips, ports, protos, iplist)

    def prepare_scan(self, ips, ports, protos, iplist):
        max_values = 100000

        # threads to use
        self.threads = int(self.threads)
        nthreads = self.threads
        total = len(list(product(ips, ports, protos)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{str(iplist)}")
        if self.proxy != "":
            print(f"{self.c.BWHITE}[✓] Outbound Proxy: {self.c.GREEN}{self.proxy}")
        print(f"{self.c.BWHITE}[✓] Port range: {self.c.GREEN}{self.rport}")
        if self.proto == "ALL":
            print(f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}UDP, TCP, TLS")
        else:
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
            print(f"{self.c.BWHITE}[✓] Customized To User:{self.c.GREEN}{self.to_user}")
        if self.to_domain != "":
            print(
                f"{self.c.BWHITE}[✓] Customized To Domain: {self.c.GREEN}{self.to_domain}"
            )
        if self.user_agent != "pplsip":
            print(
                f"{self.c.BWHITE}[✓] Customized User-Agent: {self.c.GREEN}{self.user_agent}"
            )
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}{str(nthreads)}")
        if self.file != "":
            print(
                f"{self.c.BWHITE}[✓] Loading data from file: {self.c.CYAN}{self.file}"
            )
        if self.ofile != "":
            print(
                f"{self.c.BWHITE}[✓] Saving logs info file: {self.c.CYAN}{self.ofile}"
            )
        if self.oifile != "":
            print(
                f"{self.c.BWHITE}[✓] Saving IPs info file: {self.c.CYAN}{self.oifile}"
            )
        if self.random == 1:
            print(f"{self.c.BWHITE}[✓] Random hosts: {self.c.GREEN}True")
        print(self.c.WHITE)

        values = product(ips, ports, protos)
        values2 = []
        count = 0

        iter = (a for a in enumerate(values))
        total = sum(1 for _ in iter)

        values = product(ips, ports, protos)

        start = time.time()

        for i, val in enumerate(values):
            if self.quit == False:
                if count < max_values:
                    values2.append(val)
                    count += 1

                if count == max_values or i + 1 == total:
                    try:
                        with ThreadPoolExecutor(max_workers=nthreads) as executor:
                            if self.quit == False:
                                if self.random == 1:
                                    random.shuffle(values2)

                                for j, val2 in enumerate(values2):
                                    if self.quit == False:
                                        val_ipaddr = val2[0]
                                        val_port = int(val2[1])
                                        val_proto = val2[2]
                                        scan = 1

                                        if (
                                            self.proto == "ALL"
                                            and self.rport == "5060"
                                            and val_proto == "TLS"
                                        ):
                                            val_port = 5061

                                        if self.host != "" and self.domain == "":
                                            self.domain = self.host
                                        if self.domain == "":
                                            self.domain = val_ipaddr

                                        executor.submit(
                                            self.scan_host,
                                            val_ipaddr,
                                            val_port,
                                            val_proto,
                                        )
                                try:
                                    cursor.show()
                                except: 
                                    pass
                    except KeyboardInterrupt:
                        print(f"{self.c.RED}\nYou pressed Ctrl+C!")
                        try:
                            cursor.show()
                        except:
                            pass
                        print(self.c.WHITE)
                        self.quit = True

                    values2.clear()
                    count = 0

        end = time.time()
        self.totaltime = int(end - start)

        self.found.sort()
        self.ipsfound.sort()
        self.print()
        if len(self.cve) > 0:
            self.print_cve()

        try:
            cursor.show()
        except:
            pass

    def scan_host(self, ipaddr, port, proto):
        if self.quit == False:
            try:
                cursor.hide()
            except:
                pass
            print(
                f"{self.c.BYELLOW}[{self.line[self.pos]}] Scanning {ipaddr}:{str(port)}/{proto}{' '.ljust(100)}",
                end="\r",
            )
            self.pos += 1
            if self.pos > 3:
                self.pos = 0

            try:
                if proto == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                self.fail += 1

                if self.fail > 50:
                    print(
                        f"{self.c.RED}Too many socket connection errors. Consider reducing the number of threads"
                    )
                    self.quit = True
                    return
                print(f"{self.c.RED}Failed to create socket")
                return

            bind = "0.0.0.0"
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            if self.proxy == "":
                host = (str(ipaddr), port)
            else:
                if self.proxy.find(":") > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(":")
                else:
                    proxy_ip = self.proxy
                    proxy_port = "5060"

                host = (str(proxy_ip), int(proxy_port))

            domain = self.domain
            if domain == "":
                domain = ipaddr

            contact_domain = self.contact_domain
            if contact_domain == "":
                contact_domain = "10.0.0.1"

            fdomain = self.from_domain
            tdomain = self.to_domain

            if not self.from_domain or self.from_domain == "":
                fdomain = self.domain
            if not self.to_domain or self.to_domain == "":
                tdomain = self.domain

            if self.method == "REGISTER":
                if self.to_user == "100" and self.from_user != "100":
                    self.to_user = self.from_user
                if self.to_user != "100" and self.from_user == "100":
                    self.from_user = self.to_user

            if self.proxy != "":
                self.route = "<sip:%s;lr>" % self.proxy

            msg = create_message(
                self.method,
                "",
                contact_domain,
                self.from_user,
                self.from_name,
                fdomain,
                self.to_user,
                self.to_name,
                tdomain,
                proto,
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
                self.ppi,
                self.pai,
                "",
                1,
            )

            try:
                sock.settimeout(self.timeout)

                if proto == "TCP":
                    sock.connect(host)

                if proto == "TLS":
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.load_default_certs()

                    sock_ssl = context.wrap_socket(sock, server_hostname=str(host[0]))
                    sock_ssl.connect(host)
                    sock_ssl.sendall(bytes(msg[:8192], "utf-8"))
                else:
                    sock.sendto(bytes(msg[:8192], "utf-8"), (host))

                if self.verbose == 2:
                    print(
                        f"{self.c.BWHITE}[+] Sending to {ipaddr}:{str(port)}/{proto} ..."
                    )
                    print(f"{self.c.YELLOW}{msg}")

                rescode = "100"

                while rescode[:1] == "1":
                    # receive temporary code
                    if proto == "TLS":
                        resp = sock_ssl.recv(4096)
                        (ip, rport) = host
                    else:
                        (resp, addr) = sock.recvfrom(4096)
                        (ip, rport) = host

                    headers = parse_message(resp.decode())

                    if headers and headers["response_code"] != "":
                        response = "%s %s" % (
                            headers["response_code"],
                            headers["response_text"],
                        )
                        rescode = headers["response_code"]

                    if self.verbose == 2:
                        print(
                            f"{self.c.BWHITE}[-] Receiving from {ipaddr}:{rport}/{proto} ..."
                        )
                        print(f"{self.c.GREEN}{resp.decode()}{self.c.WHITE}")

                    if headers["response_code"] == "":
                        rescode = ""
                        print(
                            f"{self.c.RED}\nEmpty response code: {self.c.YELLOW}{ipaddr}:{str(port)}/{proto}: {self.c.CYAN}{resp}\n{self.c.WHITE}"
                        )

                headers = parse_message(resp.decode())

                if headers and headers["response_code"] != "":
                    sip_type = headers["type"]
                    if self.method == "REGISTER":
                        if headers["response_code"] == "405":
                            sip_type = "Device"
                        if headers["response_code"] == "401":
                            sip_type = "Server"

                    response = "%s %s" % (
                        headers["response_code"],
                        headers["response_text"],
                    )

                    fps = fingerprinting(
                        self.method, resp.decode(), headers, self.verbose
                    )

                    fp = ""
                    for f in fps:
                        if f == "":
                            fp = "%s" % f
                        else:
                            fp += "/%s" % f

                    if fp[0:1] == "/":
                        fp = fp[1:]

                    line = "%s###%d###%s###%s###%s###%s###%s" % (
                        ip,
                        rport,
                        proto,
                        response,
                        headers["ua"],
                        sip_type,
                        fp,
                    )
                    self.found.append(line)

                    if self.oifile != "":
                        if ip not in self.ipsfound:
                            self.ipsfound.append(ip)

                    if self.verbose == 1:
                        if headers["ua"] != "":
                            print(
                                f"{self.c.WHITE}Response <{headers['response_code']} {headers['response_text']}> from {ip}:{str(rport)}/{proto} with User-Agent {headers['ua']}"
                            )
                        else:
                            print(
                                f"{self.c.WHITE}Response <{headers['response_code']} {headers['response_text']}> from {ip}:{str(rport)}/{proto} without User-Agent"
                            )

                    if headers["ua"] != "" and self.getcve == 1:
                        val = check_model(headers["ua"], fp, sip_type, self.cvelist)
                        if val != "":
                            for v in val:
                                if v not in self.cve:
                                    self.cve.append(v)
            except socket.timeout:
                pass
            except Exception as error:
                if self.verbose == 2:
                    print(f"{self.c.RED}\n{error}{self.c.WHITE}")
                pass
            finally:
                sock.close()

                if proto == "TLS":
                    sock_ssl.close()

            return headers

    def print(self):
        iplen = len("IP address")
        polen = len("Port")
        prlen = len("Proto")
        relen = len("Response")
        ualen = len("User-Agent")
        tplen = len("Type")
        fplen = len("Fingerprinting")

        for x in self.found:
            (ip, port, proto, res, ua, type, fp) = x.split("###")
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(res) > relen:
                relen = len(res)
            if len(ua) > ualen:
                ualen = len(ua)
            if len(type) > tplen:
                tplen = len(type)
            if self.fp == 1 and len(fp) > fplen:
                fplen = len(fp)

        if self.fp == 1:
            tlen = iplen + polen + prlen + relen + ualen + tplen + fplen + 20
        else:
            tlen = iplen + polen + prlen + relen + ualen + tplen + 17

        if self.fp == 1:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+{'-' * (fplen + 2)}+"
            )
        else:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+"
            )

        if self.fp == 1:
            print(
                f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} | {self.c.BWHITE}{'User-Agent'.ljust(ualen)}{self.c.WHITE} | {self.c.BWHITE}{'Type'.ljust(tplen)}{self.c.WHITE} | {self.c.BWHITE}{'Fingerprinting'.ljust(fplen)}{self.c.WHITE} |"
            )
        else:
            print(
                f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Proto'.ljust(prlen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} | {self.c.BWHITE}{'User-Agent'.ljust(ualen)}{self.c.WHITE} | {self.c.BWHITE}{'Type'.ljust(tplen)}{self.c.WHITE} |"
            )

        if self.fp == 1:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+{'-' * (fplen + 2)}+"
            )
        else:
            print(
                f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (prlen + 2)}+{'-' * (relen + 2)}+{'-' * (ualen + 2)}+{'-' * (tplen + 2)}+"
            )

        if self.oifile != "":
            if len(self.ipsfound) > 0:
                f = open(self.oifile, "a+")

                for x in self.ipsfound:
                    f.write(x + "\n")

            f.close()

        if self.ofile != "":
            f = open(self.ofile, "a+")

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (ip, port, proto, res, ua, type, fp) = x.split("###")

                if self.fp == 1:
                    print(
                        f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BBLUE}{res.ljust(relen)}{self.c.WHITE} | {self.c.BYELLOW}{ua.ljust(ualen)}{self.c.WHITE} | {self.c.BCYAN}{type.ljust(tplen)}{self.c.WHITE} | {self.c.BGREEN}{fp.ljust(fplen)}{self.c.WHITE} |"
                    )

                    if self.ofile != "":
                        f.write(
                            "%s:%s/%s => %s - %s (%s)\n"
                            % (ip, port, proto, res, ua, fp)
                        )
                else:
                    print(
                        f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {self.c.BYELLOW}{proto.ljust(prlen)}{self.c.WHITE} | {self.c.BBLUE}{res.ljust(relen)}{self.c.WHITE} | {self.c.BYELLOW}{ua.ljust(ualen)}{self.c.WHITE} | {self.c.BCYAN}{type.ljust(tplen)}{self.c.WHITE} |"
                    )

                    if self.ofile != "":
                        f.write("%s:%s/%s => %s - %s\n" % (ip, port, proto, res, ua))

        if self.fp == 1:
            print(
                self.c.WHITE
                + "+"
                + "-" * (iplen + 2)
                + "+"
                + "-" * (polen + 2)
                + "+"
                + "-" * (prlen + 2)
                + "+"
                + "-" * (relen + 2)
                + "+"
                + "-" * (ualen + 2)
                + "+"
                + "-" * (tplen + 2)
                + "+"
                + "-" * (fplen + 2)
                + "+"
            )
        else:
            print(
                self.c.WHITE
                + "+"
                + "-" * (iplen + 2)
                + "+"
                + "-" * (polen + 2)
                + "+"
                + "-" * (prlen + 2)
                + "+"
                + "-" * (relen + 2)
                + "+"
                + "-" * (ualen + 2)
                + "+"
                + "-" * (tplen + 2)
                + "+"
            )

        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)

        if self.fp == 1 and len(self.found) > 0:
            print(
                f"{self.c.YELLOW}[!] Fingerprinting is based on `To-tag` and other header values. The result may not be correct{self.c.WHITE}"
            )
            if self.method != "REGISTER":
                print(
                    f"{self.c.YELLOW}[!] Tip: You can try -m REGISTER to verify the fingerprinting result{self.c.WHITE}"
                )
            print(self.c.WHITE)

        if self.ofile != "":
            f.close()

        self.found.clear()

    def print_cve(self):
        delen = len("Device")
        velen = len("Version")
        cvlen = len("CVE")
        tylen = len("Type")
        urlen = len("URL")

        for x in self.cve:
            (de, ve, cv, ty, ur) = x.split("###")
            if len(de) > delen:
                delen = len(de)
            if len(ve) > velen:
                velen = len(ve)
            if len(cv) > cvlen:
                cvlen = len(cv)
            if len(ty) > tylen:
                tylen = len(ty)
            if len(ur) > urlen:
                urlen = len(ur)

        tlen = delen + velen + cvlen + tylen + urlen + 14

        print(f"{self.c.WHITE}+{'-' * tlen}+")
        print(
            f"{self.c.WHITE}| {self.c.BYELLOW}{'Potential known vulnerabilities'.ljust(tlen-2)}{self.c.WHITE} |"
        )
        print(
            f"{self.c.WHITE}+{'-' * (delen+2)}+{'-' * (velen+2)}+{'-' * (cvlen+2)}+{'-' * (tylen+2)}+{'-' * (urlen+2)}+"
        )
        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'Device'.ljust(delen)}{self.c.WHITE} | {self.c.BWHITE}{'Version'.ljust(velen)}{self.c.WHITE} | {self.c.BWHITE}{'CVE'.ljust(cvlen)}{self.c.WHITE} | {self.c.BWHITE}{'Type'.ljust(tylen)}{self.c.WHITE} | {self.c.BWHITE}{'URL'.ljust(urlen)}{self.c.WHITE} |"
        )
        print(
            f"{self.c.WHITE}+{'-' * (delen+2)}+{'-' * (velen+2)}+{'-' * (cvlen+2)}+{'-' * (tylen+2)}+{'-' * (urlen+2)}+"
        )

        if self.ofile != "":
            f = open(self.ofile, "a+")

        if len(self.cve) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            if self.ofile != "" and len(self.cve) > 0:
                f.write("-----\n")

            for x in self.cve:
                (de, ve, cv, ty, ur) = x.split("###")

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{de.ljust(delen)}{self.c.WHITE} | {self.c.BMAGENTA}{ve.ljust(velen)}{self.c.WHITE} | {self.c.BYELLOW}{cv.ljust(cvlen)}{self.c.WHITE} | {self.c.BCYAN}{ty.ljust(tylen)}{self.c.WHITE} | {self.c.BBLUE}{ur.ljust(urlen)}{self.c.WHITE} |"
                )
                if self.ofile != "":
                    f.write("%s %s => %s - %s - %s\n" % (de, ve, cv, ty, ur))

            if self.ofile != "" and len(self.cve) > 0:
                f.write("-----\n")

        print(
            f"{self.c.WHITE}+{'-' * (delen+2)}+{'-' * (velen+2)}+{'-' * (cvlen+2)}+{'-' * (tylen+2)}+{'-' * (urlen+2)}+"
        )
        print(self.c.WHITE)

        if self.ofile != "":
            f.close()

        self.cve.clear()
