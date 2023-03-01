#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ipaddress
import ssl
import re
import time
from lib.functions import create_message, parse_message, ip2long, long2ip, get_free_port, format_time
from lib.color import Color
from lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipExten:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.proxy = ''
        self.route = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.exten = '100-300'
        self.prefix = ''
        self.method = 'REGISTER'
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.user_agent = 'pplsip'
        self.threads = '500'
        self.verbose = '0'
        self.nocolor = ''
        self.ofile = ''
        self.filter = ''

        self.totaltime = 0
        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False

        self.c = Color()

    def start(self):
        max_values = 100000

        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['OPTIONS', 'REGISTER', 'INVITE']

        if self.nocolor == 1:
            self.c.ansy()

        self.method = self.method.upper()
        self.proto = self.proto.upper()
        if self.method == 'REGISTER':
            self.from_user = ''

        # check method
        if self.method not in supported_methods:
            print(self.c.BRED + 'Method %s is not supported' % self.method)
            sys.exit()

        # check protocol
        if self.proto != 'ALL' and self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        if self.host != '' and self.domain == '':
            self.domain = self.host
        if self.domain == '':
            self.domain = self.ip

        # create a list of IP addresses
        ips = []
        hosts = []
        for i in self.ip.split(','):
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

        logo = Logo('sipexten')
        logo.print()

        print(self.c.BWHITE+'[✓] IP/Network: ' +
              self.c.GREEN + '%s' % str(self.ip))
        if self.proxy != '':
            print(self.c.BWHITE + '[✓] Outbound Proxy: ' + self.c.GREEN + '%s' %
                  self.proxy)
        print(self.c.BWHITE+'[✓] Port: ' + self.c.GREEN + '%s' % (self.rport))
        if self.prefix != '':
            print(self.c.BWHITE+'[✓] Users prefix: ' +
                  self.c.GREEN + '%s' % self.prefix)
        print(self.c.BWHITE+'[✓] Exten range: ' +
              self.c.GREEN + '%s' % self.exten)
        print(self.c.BWHITE+'[✓] Protocol: ' +
              self.c.GREEN + '%s' % self.proto.upper())
        print(self.c.BWHITE + '[✓] Method to scan: ' +
              self.c.GREEN + '%s' % self.method)

        if self.domain != '' and self.domain != str(self.ip) and self.domain != self.host:
            print(self.c.BWHITE + '[✓] Customized Domain: ' +
                  self.c.GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(self.c.BWHITE + '[✓] Customized Contact Domain: ' + self.c.GREEN + '%s' %
                  self.contact_domain)
        if self.from_user != '100' and self.from_user != '':
            print(self.c.BWHITE + '[✓] Customized From User: ' +
                  self.c.GREEN + '%s' % self.from_user)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[✓] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)

        print(self.c.BWHITE + '[✓] Used threads: ' +
              self.c.GREEN + '%d' % nthreads)
        if nthreads > 800:
            print(self.c.BRED +
                  '[x] More than 800 threads can cause socket problems')
        if self.filter != '':
            print(self.c.BWHITE +
                  '[✓] Filter response by code: ' + self.c.CYAN + '%s' % self.filter)
        if self.ofile != '':
            print(self.c.BWHITE +
                  '[✓] Saving logs info file: ' + self.c.CYAN + '%s' % self.ofile)
        print(self.c.WHITE)

        values = product(ips, extens)
        values2 = []
        count = 0

        iter = (a for a in enumerate(values))
        total = sum(1 for _ in iter)

        values = product(ips, extens)

        start = time.time()

        for i, val in enumerate(values):
            if self.quit == False:
                if count < max_values:
                    values2.append(val)
                    count += 1

                if count == max_values or i+1 == total:
                    try:
                        with ThreadPoolExecutor(max_workers=nthreads) as executor:
                            if self.quit == False:
                                for i, val2 in enumerate(values2):
                                    val_ipaddr = val2[0]

                                    try:
                                        val_exten = int(val2[1])
                                    except:
                                        print(self.c.RED + 'Extension must be numeric. Maybe you want to use a prefix (-pr)')
                                        sys.exit()
                                    if val_exten != 0:
                                        to_user = '%s%s' % (
                                            self.prefix, val_exten)
                                    else:
                                        to_user = '%s' % self.prefix

                                    executor.submit(
                                        self.scan_host, val_ipaddr, to_user)
                    except KeyboardInterrupt:
                        print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
                        self.quit = True

                    values2.clear()
                    count = 0

        end = time.time()
        self.totaltime = int(end-start)

        self.found.sort()
        self.print()

    def scan_host(self, ipaddr, to_user):
        if self.quit == False:
            print(self.c.BYELLOW+'[%s] Scanning %s:%s/%s => Exten %s'.ljust(100) %
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
                print(self.c.RED+'Failed to create socket')
                sys.exit(1)

            bind = '0.0.0.0'
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            if self.proxy == '':
                host = (str(ipaddr), int(self.rport))
            else:
                if self.proxy.find(':') > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(':')
                else:
                    proxy_ip = self.proxy
                    proxy_port = '5060'

                host = (str(proxy_ip), int(proxy_port))

            contact_domain = self.contact_domain
            if contact_domain == '':
                contact_domain = '10.0.0.1'

            if self.proxy != '':
                self.route = '<sip:%s;lr>' % self.proxy

            if self.method == 'REGISTER':
                self.from_user = to_user

            msg = create_message(self.method, '', contact_domain, self.from_user, '', self.domain,
                                 to_user, '', self.domain, self.proto, self.domain, self.user_agent, lport, '', '', '', '1', '', '', 1, '', 0, '', self.route, '', '', '', 1)

            try:
                sock.settimeout(5)

                if self.proto == 'TCP':
                    sock.connect(host)

                if self.proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.verbose == 2:
                    print(self.c.WHITE+'[+] Sending to %s:%s/%s ...' %
                          (ipaddr, self.rport, self.proto))
                    print(self.c.WHITE+msg)

                rescode = '100'

                while rescode[:1] == '1':
                    # receive temporary code
                    if self.proto == 'TLS':
                        resp = sock_ssl.recv(4096)
                        (ipaddr, rport) = host
                    else:
                        (resp, addr) = sock.recvfrom(4096)
                        (ipaddr, rport) = addr

                    headers = parse_message(resp.decode())

                    if headers and headers['response_code'] != '':
                        response = '%s %s' % (
                            headers['response_code'], headers['response_text'])
                        rescode = headers['response_code']

                        if self.verbose == 2:
                            print(self.c.BWHITE + '[-] Receiving from %s:%s/%s ...' %
                                  (ipaddr, rport, self.proto))
                            print(self.c.GREEN + resp.decode() + self.c.WHITE)

                headers = parse_message(resp.decode())

                if headers and headers['response_code'] != '':
                    if headers['response_code'] != '404':
                        if self.filter == '' or self.filter == headers['response_code']:
                            response = '%s %s' % (
                                headers['response_code'], headers['response_text'])
                            line = '%s###%d###%s###%s###%s###%s' % (
                                ipaddr, rport, self.proto, to_user, response, headers['ua'])
                            self.found.append(line)

                    if self.verbose == 1:
                        if self.filter == '' or self.filter == headers['response_code']:
                            print(self.c.WHITE+'[Exten %s] Response <%s %s> from %s:%d/%s' %
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
        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'IP address'.ljust(iplen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Port'.ljust(polen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Proto'.ljust(prlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Extension'.ljust(exlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Response'.ljust(relen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'User-Agent'.ljust(ualen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            if self.ofile != '':
                f = open(self.ofile, 'a+')

            for x in self.found:
                (ip, port, proto, exten, res, ua) = x.split('###')

                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % port.ljust(polen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % proto.ljust(prlen) + self.c.WHITE +
                      ' | ' + self.c.BGREEN + '%s' % exten.ljust(exlen) + self.c.WHITE +
                      ' | ' + self.c.BLUE + '%s' % res.ljust(relen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % ua.ljust(ualen) + self.c.WHITE + ' |')

                if self.ofile != '':
                    f.write('%s:%s/%s => %s - %s (%s)\n' %
                            (ip, port, proto, exten, res, ua))

            if self.ofile != '':
                f.close()

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        print(self.c.BWHITE + 'Time elapsed: ' + self.c.YELLOW + '%s' %
              format_time(self.totaltime) + self.c.WHITE)
        print(self.c.WHITE)
