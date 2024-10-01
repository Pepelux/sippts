#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import random
import re
import socket
import ipaddress
import sys
import time
from IPy import IP
from asterisk.ami import AMIClient, SimpleAction

try:
    import cursor
except:
    pass

from .lib.functions import (
    get_machine_default_ip,
    ip2long,
    long2ip,
    format_time
)
from .lib.color import Color
from .lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipAstAMI:
    def __init__(self):
        self.ip = ""
        self.host = ""
        self.route = ""
        self.rport = "5038"
        self.proto = "TCP"
        self.verbose = 0
        self.file = ""
        self.nocolor = ""
        self.ofile = ""
        self.random = 0
        self.localip = ""
        self.timeout = 5
        self.threads = 200
        self.user = "admin"
        self.pwd = "amp111"
        self.cmd = ""

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
        print(self.c.WHITE)
        self.quit = True


    def start(self):
        try:
            self.verbose == int(self.verbose)
        except:
            self.verbose = 0

        supported_protos = ["TCP", "TLS"]

        if self.nocolor == 1:
            self.c.ansy()

        self.proto = self.proto.upper()
        if self.proto == "TCP|TLS":
            self.proto = "ALL"

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

        logo = Logo("astami")
        logo.print()

        # create a list of protocols
        protos = []
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
                            ips.append(long2ip(i))

                except:
                    if ips == []:
                        ips.append(self.ip)
                        iplist = self.ip

            self.prepare_scan(ips, ports, protos, iplist)


    def prepare_scan(self, ips, ports, protos, iplist):
        max_values = 100000
        
        # threads to use
        nthreads = self.threads
        total = len(list(product(ips, ports, protos)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{str(iplist)}")
        print(f"{self.c.BWHITE}[✓] Remote port: {self.c.GREEN}{self.rport}")
        if self.proto == "ALL":
            print(f"{self.c.BWHITE}[✓] Protocols: {self.c.GREEN}TCP, TLS")
        else:
            print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}{self.proto.upper()}")
        if self.ofile != "":
            print(
                f"{self.c.BWHITE}[✓] Saving logs info file: {self.c.CYAN}{self.ofile}"
            )
        if self.random == 1:
            print(f"{self.c.BWHITE}[✓] Random hosts: {self.c.GREEN}True")
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}{str(nthreads)}")
        print(f"{self.c.BWHITE}[✓] Username: {self.c.GREEN}{self.user}")
        print(f"{self.c.BWHITE}[✓] Password: {self.c.GREEN}{self.pwd}")
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

                                        if (
                                            self.proto == "ALL"
                                            and self.rport == "5060"
                                            and val_proto == "TLS"
                                        ):
                                            val_port = 5061

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
 
 
    def callback_response(self, response):
        return response

    
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

            amiclient = AMIClient(address=ipaddr,port=port)

            try:
                if self.verbose == 2:
                    print(f"\n{self.c.BWHITE}login(username='{self.user}',secret='{self.pwd}')")

                con = amiclient.login(username=self.user,secret=self.pwd, callback=self.callback_response)
                
                response = con.response

                if self.verbose == 2:
                    print(f"\n{self.c.WHITE}{response}")
                
                message = ''
                if hasattr(response, 'keys') and isinstance(response.keys, dict):
                    message = response.keys.get('Message', '') 

                rcolor = self.c.BBLUE
                
                if response.status == "Error":
                    rcolor = self.c.BRED
                else:
                    rcolor = self.c.BGREEN

                if self.verbose > 0:
                    print(f"{self.c.BYELLOW}[{self.line[self.pos]}] Scanning {ipaddr}:{str(port)}/TCP ... {rcolor}{message}{self.c.WHITE}{' '.ljust(100)}")

                output = ''
                if response.status == "Success":
                    action = SimpleAction(
                        'Command',
                        Command='core show version'
                    )
                    resp = amiclient.send_action(action)
                    response = resp.response

                    if hasattr(response, 'keys') and isinstance(response.keys, dict):
                        output = response.keys.get('Output', '') 

                line = f"{ipaddr}###{str(port)}###{response.status}###{message}###{output}"
                self.found.append(line)

                output = ''
                if response.status == "Success" and self.cmd != '':
                    print(f'{self.c.WHITE}\n\n/--------------------/')
                    print(f"{self.c.BWHITE}Command: '{self.cmd}'")

                    action = SimpleAction(
                        'Command',
                        Command=f'{self.cmd}'
                    )
                    resp = amiclient.send_action(action)
                    response = resp.response

                    if self.verbose == 2:
                        print(f"{self.c.WHITE}{response}")

                    if hasattr(response, 'keys') and isinstance(response.keys, dict):
                        output = response.keys.get('Output', '') 

                    if self.verbose < 2:
                        print(f"{self.c.WHITE}{output}")
                        
                    print('/--------------------/')

            except:
                if self.verbose == 2:
                    print(f"{self.c.BYELLOW}[{self.line[self.pos]}] Scanning {ipaddr}:{str(port)}/TCP ... {self.c.RED}Connection Error{self.c.WHITE}{' '.ljust(100)}")

                pass

            amiclient.logoff()
            cursor.show()


    def print(self):
        iplen = len("IP address")
        polen = len("Port")
        relen = len("Response")
        velen = len("Version")

        for x in self.found:
            (ip, port, status, res, ver) = x.split("###")
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(res) > relen:
                relen = len(res)
            if len(ver) > velen:
                velen = len(ver)

        tlen = iplen + polen + relen + velen + 11
        
        print(self.c.WHITE)

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (relen + 2)}+{'-' * (velen + 2)}+"
        )

        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'IP address'.ljust(iplen)}{self.c.WHITE} | {self.c.BWHITE}{'Port'.ljust(polen)}{self.c.WHITE} | {self.c.BWHITE}{'Response'.ljust(relen)}{self.c.WHITE} | {self.c.BWHITE}{'Version'.ljust(velen)}{self.c.WHITE} |"
        )

        print(
            f"{self.c.WHITE}+{'-' * (iplen + 2)}+{'-' * (polen + 2)}+{'-' * (relen + 2)}+{'-' * (velen + 2)}+"
        )

        if self.ofile != "":
            f = open(self.ofile, "a+")

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (ip, port, status, res, ver) = x.split("###")
                
                rcolor = self.c.BBLUE
                
                if status == "Error":
                    rcolor = self.c.RED

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{ip.ljust(iplen)}{self.c.WHITE} | {self.c.BMAGENTA}{port.ljust(polen)}{self.c.WHITE} | {rcolor}{res.ljust(relen)}{self.c.WHITE} | {self.c.BYELLOW}{ver.ljust(velen)}{self.c.WHITE} |"
                )

                if self.ofile != "":
                    f.write(f"{ip}:{port} => {res} ({self.user}/{self.pwd}) - {ver}\n")

        print(
            self.c.WHITE
            + "+"
            + "-" * (iplen + 2)
            + "+"
            + "-" * (polen + 2)
            + "+"
            + "-" * (relen + 2)
            + "+"
            + "-" * (velen + 2)
            + "+"
        )

        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)

        if self.ofile != "":
            f.close()

        self.found.clear()

