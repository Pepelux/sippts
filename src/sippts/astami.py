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
import sys
import time
from asterisk.ami import AMIClient, SimpleAction

try:
    import cursor
except:
    pass

from .lib.functions import (
    open_log,
    get_machine_default_ip,
    expand_targets,
    host_sort_key,
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
        # reset the stop flag: after a Ctrl+C the object kept it set, so from
        # sippts-gui (where the module instance is reused) every later run
        # did nothing at all
        self.quit = False

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.timeout = int(self.timeout)
        except (TypeError, ValueError):
            self.timeout = 5

        if self.nocolor == 1:
            self.c.ansy()

        # AMI connections are always TCP
        self.proto = "TCP"

        # my IP address
        local_ip = self.localip
        if self.localip == "":
            try:
                local_ip = get_machine_default_ip()
                self.localip = local_ip
            except:
                print(f"{self.c.BRED}Error getting local IP")
                print(
                    f"{self.c.BWHITE}Try with {self.c.BYELLOW}-local-ip{self.c.BWHITE} param"
                )
                print(self.c.WHITE)
                sys.exit()

        logo = Logo("astami", self.nocolor)
        logo.print()

        # AMI connections are always TCP
        protos = ["TCP"]

        # create a list of ports
        ports = []
        for p in self.rport.split(","):
            p = p.strip()
            m = re.fullmatch(r"([0-9]+)-([0-9]+)", p)
            if m:
                pini = max(int(m.group(1)), 1)
                pend = min(int(m.group(2)), 65535)

                for x in range(pini, pend + 1):
                    ports.append(x)
            else:
                if not p.isdigit() or int(p) < 1 or int(p) > 65535:
                    print(f"{self.c.BRED}Invalid port {p} (valid range is 1-65535)")
                    print(self.c.WHITE)
                    sys.exit()

                ports.append(int(p))

        if ports == []:
            print(f"{self.c.BRED}No valid ports to scan in {self.rport}")
            print(self.c.WHITE)
            sys.exit()

        # create a list of IP addresses
        if self.file != "":
            try:
                f = open(self.file)
            except OSError:
                print(f"{self.c.RED}Error reading file {self.file}")
                print(self.c.WHITE)
                sys.exit()

            with f:
                for line in f:
                    if self.quit == True:
                        break

                    line = line.strip()

                    if line == "":
                        continue

                    try:
                        (ips, names) = expand_targets(line)
                    except ValueError as error:
                        print(f"{self.c.RED}{error}")
                        print(self.c.WHITE)
                        continue

                    ips = [ip for ip in ips if ip != self.localip]

                    self.prepare_scan(ips, ports, protos, line)
        else:
            try:
                (ips, names) = expand_targets(self.ip)
            except ValueError as error:
                print(f"{self.c.RED}{error}")
                print(self.c.WHITE)
                sys.exit()

            if ips == []:
                print(f"{self.c.RED}No target to scan in {self.ip}")
                print(self.c.WHITE)
                sys.exit()

            ips = [ip for ip in ips if ip != self.localip]

            self.prepare_scan(ips, ports, protos, self.ip)


    def prepare_scan(self, ips, ports, protos, iplist):
        max_values = 100000
        
        # threads to use
        nthreads = self.threads
        total = len(ips) * len(ports) * len(protos)
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(f"{self.c.BWHITE}[✓] IP/Network: {self.c.GREEN}{str(iplist)}")
        print(f"{self.c.BWHITE}[✓] Remote port: {self.c.GREEN}{self.rport}")
        print(f"{self.c.BWHITE}[✓] Protocol: {self.c.GREEN}TCP")
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

        self.found.sort(key=host_sort_key)
        self.ipsfound.sort(key=host_sort_key)
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

            # -t was accepted and never used: the client kept its own default
            amiclient = AMIClient(address=ipaddr, port=port, timeout=self.timeout)

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

                # the 'core show version' block below rebinds response, so the
                # login status has to be kept aside: the table used to show the
                # status of the Command action (usually 'Follows'), and -x was
                # gated on it, so the user command never ran after a successful
                # login
                login_status = response.status

                rcolor = self.c.BBLUE
                
                if login_status == "Error":
                    rcolor = self.c.BRED
                else:
                    rcolor = self.c.BGREEN

                if self.verbose > 0:
                    print(f"{self.c.BYELLOW}[{self.line[self.pos]}] Scanning {ipaddr}:{str(port)}/TCP ... {rcolor}{message}{self.c.WHITE}{' '.ljust(100)}")

                output = ''
                if login_status == "Success":
                    action = SimpleAction(
                        'Command',
                        Command='core show version'
                    )
                    resp = amiclient.send_action(action)
                    response = resp.response

                    if hasattr(response, 'keys') and isinstance(response.keys, dict):
                        output = response.keys.get('Output', '') 

                line = f"{ipaddr}###{str(port)}###{login_status}###{message}###{output}"
                self.found.append(line)

                output = ''
                if login_status == "Success" and self.cmd != '':
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

            # logoff() on a connection that never came up raises, and the
            # unguarded cursor.show() was a NameError when cursor is not
            # installed (the import at the top is optional): both killed the
            # worker thread silently and left the cursor hidden
            try:
                amiclient.logoff()
            except:
                pass

            try:
                cursor.show()
            except:
                pass


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
            f = open_log(self.ofile)

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

