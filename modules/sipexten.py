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
from lib.functions import create_message, parse_message, ip2long, long2ip, get_free_port
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


class SipExten:
    def __init__(self):
        self.ip = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.exten = '100-300'
        self.prefix = ''
        self.method = 'REGISTER'
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.user_agent = 'pplsip'
        self.threads = '100'
        self.verbose = '0'

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['OPTIONS', 'REGISTER', 'INVITE']

        self.method = self.method.upper()
        self.proto = self.proto.upper()
        if self.method == 'REGISTER':
            self.from_user = ''

        # check method
        if self.method not in supported_methods:
            print(BRED + 'Method %s is not supported' % self.method)
            sys.exit()

        # check protocol
        if self.proto != 'ALL' and self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # create a list of IP addresses
        ips = []
        hosts = list(ipaddress.ip_network(str(self.ip)).hosts())
        last = len(hosts)-1
        start_ip = hosts[0]
        end_ip = hosts[last]

        ipini = int(ip2long(str(start_ip)))
        ipend = int(ip2long(str(end_ip)))

        for i in range(ipini, ipend+1):
            ips.append(long2ip(i))

        # create a list of extens
        extens = []
        for p in self.exten.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    extens.append(x)
            else:
                extens.append(p)

        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(ips, extens)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(BWHITE+'[!] IP/Network: ' + GREEN + '%s' % str(self.ip))
        print(BWHITE+'[!] Port: ' + GREEN + '%s' % (self.rport))
        if self.prefix != '':
            print(BWHITE+'[!] Users prefix: ' + GREEN + '%s' % self.prefix)
        print(BWHITE+'[!] Exten range: ' + GREEN + '%s' % self.exten)
        print(BWHITE+'[!] Protocol: ' + GREEN + '%s' % self.proto.upper())
        print(BWHITE + '[!] Method to scan: ' + GREEN + '%s' % self.method)

        if self.domain != '':
            print(BWHITE + '[!] Customized Domain: ' +
                  GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(BWHITE + '[!] Customized Contact Domain: ' + GREEN + '%s' %
                  self.contact_domain)
        if self.from_user != '100' and self.from_user != '':
            print(BWHITE + '[!] Customized From User: ' +
                  GREEN + '%s' % self.from_user)
        if self.user_agent != 'pplsip':
            print(BWHITE + '[!] Customized User-Agent: ' +
                  GREEN + '%s' % self.user_agent)

        print(BWHITE+'[!] Total threads: ' + GREEN + '%d' % nthreads)
        print(WHITE)

        values = product(ips, extens)

        try:
            with ThreadPoolExecutor(max_workers=nthreads) as executor:
                if self.quit == False:
                    for i, val in enumerate(values):
                        val_ipaddr = val[0]
                        val_exten = int(val[1])
                        if val_exten != 0:
                            to_user = '%s%s' % (self.prefix, val_exten)
                        else:
                            to_user = '%s' % self.prefix
                        if not self.domain or self.domain == '':
                            self.domain = val_ipaddr

                        executor.submit(self.scan_host, val_ipaddr, to_user)
        except KeyboardInterrupt:
            print(RED + '\nYou pressed Ctrl+C!' + WHITE)
            self.quit = True

        self.found.sort()
        self.print()

    def scan_host(self, ipaddr, to_user):
        if self.quit == False:
            print(BYELLOW+'[%s] Scanning %s:%s/%s => Exten %s'.ljust(100) %
                  (self.line[self.pos], ipaddr, self.rport, self.proto, to_user), end="\r")

            self.pos += 1
            if self.pos > 3:
                self.pos = 0

            try:
                if self.proto == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(RED+'Failed to create socket')
                sys.exit(1)

            bind = '0.0.0.0'
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            host = (str(ipaddr), int(self.rport))

            domain = self.domain
            if domain == '':
                domain = ipaddr

            contact_domain = self.contact_domain
            if contact_domain == '':
                contact_domain = '10.0.0.1'

            if self.method == 'REGISTER':
                self.from_user = to_user

            msg = create_message(self.method, contact_domain, self.from_user, '',
                                 to_user, '', self.proto, domain, self.user_agent, lport, '', '', '', 1, '', '', '', 0)

            try:
                sock.settimeout(5)

                if self.proto == 'TCP':
                    sock.connect(host)

                if self.proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.verbose == 2:
                    print(WHITE+'[+] Sending to %s:%s/%s ...' %
                          (ipaddr, self.rport, self.proto))
                    print(WHITE+msg)

                if self.proto == 'TLS':
                    (resp, addr) = sock_ssl.recv(4096)
                    (ipaddr, rport) = host
                else:
                    (resp, addr) = sock.recvfrom(4096)
                    (ipaddr, rport) = addr

                if self.verbose == 2:
                    print(WHITE+'[+] Receiving from %s:%d ...' %
                          (ipaddr, rport))
                    print(WHITE+resp.decode())

                headers = parse_message(resp.decode())

                if headers:
                    if headers['response_code'] != '404':
                        response = '%s %s' % (
                            headers['response_code'], headers['response_text'])
                        line = '%s###%d###%s###%s###%s###%s' % (
                            ipaddr, rport, self.proto, to_user, response, headers['ua'])
                        self.found.append(line)

                    if self.verbose == 1:
                        print(WHITE+'[Exten %s] Response <%s %s> from %s:%d/%s' %
                              (to_user, headers['response_code'], headers['response_text'], ipaddr, rport, self.proto))

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
        exlen = len('Extension')
        relen = len('Response')
        ualen = len('User-Agent')

        for x in self.found:
            (ip, port, proto, exten, res, ua) = x.split('###')
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

        tlen = iplen+polen+prlen+exlen+relen+ualen+17
        print(WHITE + ' ' + '-' * tlen)
        print(WHITE +
              '| ' + BWHITE + 'IP address'.ljust(iplen) + WHITE +
              ' | ' + BWHITE + 'Port'.ljust(polen) + WHITE +
              ' | ' + BWHITE + 'Proto'.ljust(prlen) + WHITE +
              ' | ' + BWHITE + 'Extension'.ljust(exlen) + WHITE +
              ' | ' + BWHITE + 'Response'.ljust(relen) + WHITE +
              ' | ' + BWHITE + 'User-Agent'.ljust(ualen) + WHITE + ' |')
        print(WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(WHITE + '| ' + WHITE + 'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (ip, port, proto, exten, res, ua) = x.split('###')

                print(WHITE +
                      '| ' + BGREEN + '%s' % ip.ljust(iplen) + WHITE +
                      ' | ' + GREEN + '%s' % port.ljust(polen) + WHITE +
                      ' | ' + GREEN + '%s' % proto.ljust(prlen) + WHITE +
                      ' | ' + BGREEN + '%s' % exten.ljust(exlen) + WHITE +
                      ' | ' + BLUE + '%s' % res.ljust(relen) + WHITE +
                      ' | ' + YELLOW + '%s' % ua.ljust(ualen) + WHITE + ' |')

        print(WHITE + ' ' + '-' * tlen)
        print(WHITE)
