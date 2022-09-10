#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ipaddress
import ssl
import re
from IPy import IP
from lib.functions import create_message, parse_message, get_machine_default_ip, ip2long, long2ip, get_free_port, ping
from itertools import product
from concurrent.futures import ThreadPoolExecutor

BRED = '\033[1;31;40m'
RED = '\033[0;31;40m'
BRED_BLACK = '\033[1;30;41m'
RED_BLACK = '\033[0;30;41m'
BGREEN = '\033[1;32;40m'
GREEN = '\033[0;32;40m'
BGREEN_BLACK = '\033[1;30;42m'
GREEN_BLACK = '\033[0;30;42m'
BYELLOW = '\033[1;33;40m'
YELLOW = '\033[0;33;40m'
BBLUE = '\033[1;34;40m'
BLUE = '\033[0;34;40m'
BMAGENTA = '\033[1;35;40m'
MAGENTA = '\033[0;35;40m'
BCYAN = '\033[1;36;40m'
CYAN = '\033[0;36;40m'
BWHITE = '\033[1;37;40m'
WHITE = '\033[0;37;40m'


class SipScan:
    def __init__(self):
        self.ip = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.method = 'OPTIONS'
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.from_name = ''
        self.from_domain = ''
        self.to_user = '100'
        self.to_name = ''
        self.to_domain = ''
        self.user_agent = 'pplsip'
        self.threads = '100'
        self.verbose = '0'
        self.ping = 'False'
        self.file = ''

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False

    # def __del__(self):
    #     print('SIPScan destruido')

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['OPTIONS', 'REGISTER', 'INVITE']

        self.method = self.method.upper()
        self.proto = self.proto.upper()
        if self.proto == 'UDP|TCP|TLS':
            self.proto = 'ALL'
        if self.ping == 1:
            self.ping = 'True'
        else:
            self.ping = 'False'

        # check method
        if self.method not in supported_methods:
            print(BRED + 'Method %s is not supported' % self.method)
            sys.exit()

        # check protocol
        if self.proto != 'ALL' and self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # my IP address
        local_ip = get_machine_default_ip()

        # if rport is by default but we want to scan TLS protocol, also try with port 5061
        if self.rport == '5060' and (self.proto == 'TLS' or self.proto == 'ALL'):
            self.rport = '5060-5061'

        # create a list of protocols
        protos = []
        if self.proto == 'UDP' or self.proto == 'ALL':
            protos.append('UDP')
        if self.proto == 'TCP' or self.proto == 'ALL':
            protos.append('TCP')
        if self.proto == 'TLS' or self.proto == 'ALL':
            protos.append('TLS')

        # create a list of ports
        ports = []
        for p in self.rport.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    ports.append(x)
            else:
                ports.append(p)

        # create a list of IP addresses
        ips = []

        if self.file != '':
            try:
                with open(self.file) as f:
                    line = f.readline()

                    while(line):
                        try:
                            ip = socket.gethostbyname(line)
                            line = IP(ip)
                        except:
                            line = IP(line)

                        hosts = list(ipaddress.ip_network(str(line)).hosts())

                        if hosts == []:
                            hosts.append(self.ip)

                        last = len(hosts)-1
                        start_ip = hosts[0]
                        end_ip = hosts[last]

                        ipini = int(ip2long(str(start_ip)))
                        ipend = int(ip2long(str(end_ip)))

                        for i in range(ipini, ipend+1):
                            if i != local_ip:
                                if self.ping == 'False':
                                    ips.append(long2ip(i))
                                else:
                                    print(YELLOW + '[+] Ping %s ...' %
                                          str(long2ip(i)) + WHITE, end='\r')

                                    if ping(long2ip(i), '0.1') == True:
                                        print(GREEN + '\n   [-] ... Pong %s' %
                                              str(long2ip(i)) + WHITE)
                                        ips.append(long2ip(i))

                        line = f.readline()

                f.close()
            except:
                print('Error opening file %s' % self.file)
                exit()
        else:
            hosts = list(ipaddress.ip_network(str(self.ip)).hosts())

            if hosts == []:
                hosts.append(self.ip)

            last = len(hosts)-1
            start_ip = hosts[0]
            end_ip = hosts[last]

            ipini = int(ip2long(str(start_ip)))
            ipend = int(ip2long(str(end_ip)))

            for i in range(ipini, ipend+1):
                if i != local_ip:
                    if self.ping == 'False':
                        ips.append(long2ip(i))
                    else:
                        print(YELLOW + '[+] Ping %s ...' %
                              str(long2ip(i)) + WHITE, end='\r')

                        if ping(long2ip(i), '0.1') == True:
                            print(GREEN + '\n   [-] ... Pong %s' %
                                  str(long2ip(i)) + WHITE)
                            ips.append(long2ip(i))

        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(ips, ports, protos)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(BWHITE + '[!] IP/Network: ' + GREEN + '%s' % str(self.ip))

        print(BWHITE + '[!] Port range: ' + GREEN + '%s' % self.rport)
        if self.proto == 'ALL':
            print(BWHITE + '[!] Protocols: ' + GREEN + 'UDP, TCP, TLS')
        else:
            print(BWHITE + '[!] Protocol: ' + GREEN + '%s' %
                  self.proto.upper())

        print(BWHITE + '[!] Method to scan: ' + GREEN + '%s' % self.method)

        if self.domain != '' and self.domain != str(self.ip):
            print(BWHITE + '[!] Customized Domain: ' +
                  GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(BWHITE + '[!] Customized Contact Domain: ' + GREEN + '%s' %
                  self.contact_domain)
        if self.from_name != '':
            print(BWHITE + '[!] Customized From Name: ' +
                  GREEN + '%s' % self.from_name)
        if self.from_user != '100':
            print(BWHITE + '[!] Customized From User: ' +
                  GREEN + '%s' % self.from_user)
        if self.from_domain != '':
            print(BWHITE + '[!] Customized From Domain: ' +
                  GREEN + '%s' % self.from_domain)
        if self.to_name != '':
            print(BWHITE + '[!] Customized To Name: ' +
                  GREEN + '%s' % self.to_name)
        if self.to_user != '100':
            print(BWHITE + '[!] Customized To User:' +
                  GREEN + ' %s' % self.to_user)
        if self.to_domain != '':
            print(BWHITE + '[!] Customized To Domain: ' +
                  GREEN + '%s' % self.to_domain)
        if self.user_agent != 'pplsip':
            print(BWHITE + '[!] Customized User-Agent: ' +
                  GREEN + '%s' % self.user_agent)

        print(BWHITE + '[!] Used threads: ' + GREEN + '%d' % nthreads)
        if nthreads > 200:
            print(BRED + '[x] More than 200 threads can cause socket problems')
        print(WHITE)

        values = product(ips, ports, protos)

        try:
            with ThreadPoolExecutor(max_workers=nthreads) as executor:
                if self.quit == False:
                    for i, val in enumerate(values):
                        val_ipaddr = val[0]
                        val_port = int(val[1])
                        val_proto = val[2]

                        if not self.domain or self.domain == '':
                            self.domain = val_ipaddr
                        if not self.from_domain or self.from_domain == '':
                            self.from_domain = val_ipaddr
                        if not self.to_domain or self.to_domain == '':
                            self.to_domain = val_ipaddr

                        executor.submit(self.scan_host, val_ipaddr,
                                        val_port, val_proto)
        except KeyboardInterrupt:
            print(RED + '\nYou pressed Ctrl+C!' + WHITE)
            self.quit = True

        self.found.sort()
        self.print()

    def scan_host(self, ipaddr, port, proto):
        if self.quit == False:
            print(BYELLOW + '[%s] Scanning %s:%d/%s'.ljust(100) %
                  (self.line[self.pos], ipaddr, port, proto), end='\r')

            self.pos += 1
            if self.pos > 3:
                self.pos = 0

            try:
                if proto == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(RED + 'Failed to create socket')
                sys.exit(1)

            bind = '0.0.0.0'
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            host = (str(ipaddr), port)

            domain = self.domain
            if domain == '':
                domain = ipaddr

            contact_domain = self.contact_domain
            if contact_domain == '':
                contact_domain = '10.0.0.1'

            msg = create_message(self.method, contact_domain, self.from_user, self.from_name, self.from_domain,
                                 self.to_user, self.to_name, self.to_domain, proto, domain, self.user_agent, lport, '', '', '', '1', '', '', '', 0)

            try:
                sock.settimeout(2)

                if proto == 'TCP':
                    sock.connect(host)

                if proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.verbose == 2:
                    print(BWHITE + '[+] Sending to %s:%d/%s ...' %
                          (ipaddr, port, proto))
                    print(YELLOW + msg)

                if proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                    (ip, rport) = host
                else:
                    (resp, addr) = sock.recvfrom(4096)
                    (ip, rport) = addr

                if self.verbose == 2:
                    print(BWHITE + '[+] Receiving from %s:%d ...' %
                          (ip, rport))
                    print(GREEN + resp.decode())

                headers = parse_message(resp.decode())

                if headers:
                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    line = '%s###%d###%s###%s###%s' % (
                        ip, rport, proto, response, headers['ua'])
                    self.found.append(line)

                    if self.verbose == 1:
                        if headers['ua'] != '':
                            print(WHITE + 'Response <%s %s> from %s:%d/%s with User-Agent %s' %
                                  (headers['response_code'], headers['response_text'], ip, rport, proto, headers['ua']))
                        else:
                            print(WHITE + 'Response <%s %s> from %s:%d/%s without User-Agent' %
                                  (headers['response_code'], headers['response_text'], ip, rport, proto))

                return headers
            except socket.timeout:
                pass
            except:
                pass
            finally:
                sock.close()

    def print(self):
        iplen = len('IP address')
        polen = len('Port')
        prlen = len('Proto')
        relen = len('Response')
        ualen = len('User-Agent')

        for x in self.found:
            (ip, port, proto, res, ua) = x.split('###')
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

        tlen = iplen+polen+prlen+relen+ualen+14
        print(WHITE + ' ' + '-' * tlen)
        print(WHITE +
              '| ' + BWHITE + 'IP address'.ljust(iplen) + WHITE +
              ' | ' + BWHITE + 'Port'.ljust(polen) + WHITE +
              ' | ' + BWHITE + 'Proto'.ljust(prlen) + WHITE +
              ' | ' + BWHITE + 'Response'.ljust(relen) + WHITE +
              ' | ' + BWHITE + 'User-Agent'.ljust(ualen) + WHITE + ' |')
        print(WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(WHITE + '| ' + WHITE + 'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (ip, port, proto, res, ua) = x.split('###')

                print(WHITE +
                      '| ' + BGREEN + '%s' % ip.ljust(iplen) + WHITE +
                      ' | ' + GREEN + '%s' % port.ljust(polen) + WHITE +
                      ' | ' + GREEN + '%s' % proto.ljust(prlen) + WHITE +
                      ' | ' + BLUE + '%s' % res.ljust(relen) + WHITE +
                      ' | ' + YELLOW + '%s' % ua.ljust(ualen) + WHITE + ' |')

        print(WHITE + ' ' + '-' * tlen)
        print(WHITE)
