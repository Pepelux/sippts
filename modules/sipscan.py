#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import random
import socket
import sys
import ipaddress
import ssl
import re
import time
from IPy import IP
from lib.functions import create_message, parse_message, get_machine_default_ip, ip2long, long2ip, get_free_port, ping, fingerprinting, format_time
from lib.color import Color
from lib.logos import Logo
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipScan:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.proxy = ''
        self.route = ''
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
        self.threads = '500'
        self.verbose = '0'
        self.ping = 'False'
        self.file = ''
        self.nocolor = ''
        self.ofile = ''
        self.fp = '0'
        self.random = 0
        self.ppi = ''
        self.pai = ''
        self.localip = ''

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False
        self.totaltime = 0

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['OPTIONS', 'REGISTER', 'INVITE']

        if self.nocolor == 1:
            self.c.ansy()

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
            print(self.c.BRED + 'Method %s is not supported' % self.method)
            sys.exit()

        # check protocol
        if self.proto != 'ALL' and self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # my IP address
        local_ip = self.localip
        if self.localip == '':
            local_ip = get_machine_default_ip()
            self.localip = local_ip

        # if rport is by default but we want to scan TLS protocol, also try with port 5061
        if self.rport == '5060' and (self.proto == 'TLS' or self.proto == 'ALL'):
            self.rport = '5060-5061'

        if self.rport.upper() == 'ALL':
            self.rport = '1-65536'

        logo = Logo('sipscan')
        logo.print()

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
                    ports.append(str(x))
            else:
                ports.append(p)

        # create a list of IP addresses
        if self.file != '':
            try:
                with open(self.file) as f:
                    line = f.readline()
                    line = line.replace('\n', '')

                    while (line):
                        error = 0

                        try:
                            if self.quit == False:
                                try:
                                    ip = socket.gethostbyname(line)
                                    self.ip = IP(ip, make_net=True)
                                except:
                                    try:
                                        self.ip = IP(line, make_net=True)

                                    except:
                                        if line.find('-') > 0:
                                            val = line.split('-')
                                            start_ip = val[0]
                                            end_ip = val[1]
                                            self.ip = line

                                            error = 1

                                ips = []

                                if error == 0:
                                    hosts = list(ipaddress.ip_network(
                                        str(self.ip)).hosts())

                                    if hosts == []:
                                        hosts.append(self.ip)

                                    last = len(hosts)-1
                                    start_ip = hosts[0]
                                    end_ip = hosts[last]

                                ipini = int(ip2long(str(start_ip)))
                                ipend = int(ip2long(str(end_ip)))

                                for i in range(ipini, ipend+1):
                                    if i != self.localip and long2ip(i)[-2:] != '.0' and long2ip(i)[-4:] != '.255':
                                        if self.ping == 'False':
                                            ips.append(long2ip(i))
                                        else:
                                            print(self.c.YELLOW + '[+] Ping %s ...' %
                                                  str(long2ip(i)) + self.c.WHITE, end='\r')

                                            if ping(long2ip(i), '0.1') == True:
                                                print(self.c.GREEN + '\n   [-] ... Pong %s' %
                                                      str(long2ip(i)) + self.c.WHITE)
                                                ips.append(long2ip(i))

                                self.prepare_scan(ips, ports, protos, self.ip)
                        except:
                            pass

                        line = f.readline()

                f.close()
            except:
                print('Error reading file %s' % self.file)
                exit()
        else:
            for i in self.ip.split(','):
                ips = []
                hosts = []
                error = 0

                try:
                    if i.find('/') < 1:
                        i = socket.gethostbyname(i)
                        i = IP(i, make_net=True)
                    else:
                        i = IP(i, make_net=True)
                except:
                    if i.find('-') > 0:
                        val = i.split('-')
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

                        last = len(hosts)-1
                        start_ip = hosts[0]
                        end_ip = hosts[last]

                    ipini = int(ip2long(str(start_ip)))
                    ipend = int(ip2long(str(end_ip)))
                    iplist = i

                    for i in range(ipini, ipend+1):
                        if i != self.localip and long2ip(i)[-2:] != '.0' and long2ip(i)[-4:] != '.255':
                            if self.ping == 'False':
                                ips.append(long2ip(i))
                            else:
                                print(self.c.YELLOW + '[+] Ping %s ...' %
                                      str(long2ip(i)) + self.c.WHITE, end='\r')

                                if ping(long2ip(i), '0.1') == True:
                                    print(self.c.GREEN + '\n   [-] ... Pong %s' %
                                          str(long2ip(i)) + self.c.WHITE)
                                    ips.append(long2ip(i))

                    self.prepare_scan(ips, ports, protos, iplist)
                except:
                    pass

    def prepare_scan(self, ips, ports, protos, iplist):
        max_values = 100000

        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(ips, ports, protos)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % str(iplist))
        if self.proxy != '':
            print(self.c.BWHITE + '[✓] Outbound Proxy: ' + self.c.GREEN + '%s' %
                  self.proxy)
        print(self.c.BWHITE + '[✓] Port range: ' +
              self.c.GREEN + '%s' % self.rport)
        if self.proto == 'ALL':
            print(self.c.BWHITE + '[✓] Protocols: ' +
                  self.c.GREEN + 'UDP, TCP, TLS')
        else:
            print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
                  self.proto.upper())

        print(self.c.BWHITE + '[✓] Method to scan: ' +
              self.c.GREEN + '%s' % self.method)

        if self.domain != '' and self.domain != str(self.ip) and self.domain != self.host:
            print(self.c.BWHITE + '[✓] Customized Domain: ' +
                  self.c.GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(self.c.BWHITE + '[✓] Customized Contact Domain: ' + self.c.GREEN + '%s' %
                  self.contact_domain)
        if self.from_name != '':
            print(self.c.BWHITE + '[✓] Customized From Name: ' +
                  self.c.GREEN + '%s' % self.from_name)
        if self.from_user != '100':
            print(self.c.BWHITE + '[✓] Customized From User: ' +
                  self.c.GREEN + '%s' % self.from_user)
        if self.from_domain != '':
            print(self.c.BWHITE + '[✓] Customized From Domain: ' +
                  self.c.GREEN + '%s' % self.from_domain)
        if self.to_name != '':
            print(self.c.BWHITE + '[✓] Customized To Name: ' +
                  self.c.GREEN + '%s' % self.to_name)
        if self.to_user != '100':
            print(self.c.BWHITE + '[✓] Customized To User:' +
                  self.c.GREEN + ' %s' % self.to_user)
        if self.to_domain != '':
            print(self.c.BWHITE + '[✓] Customized To Domain: ' +
                  self.c.GREEN + '%s' % self.to_domain)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[✓] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)
        print(self.c.BWHITE + '[✓] Used threads: ' +
              self.c.GREEN + '%d' % nthreads)
        if nthreads > 800:
            print(self.c.BRED +
                  '[x] More than 800 threads can cause socket problems')
        if self.file != '':
            print(self.c.BWHITE + '[✓] Loading data from file: ' +
                  self.c.CYAN + '%s' % self.file)
        if self.ofile != '':
            print(self.c.BWHITE + '[✓] Saving logs info file: ' +
                  self.c.CYAN + '%s' % self.ofile)
        if self.random == 1:
            print(self.c.BWHITE + '[✓] Random hosts: ' +
                  self.c.GREEN + 'True')
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

                if count == max_values or i+1 == total:
                    try:
                        with ThreadPoolExecutor(max_workers=nthreads) as executor:
                            if self.quit == False:
                                if self.random == 1:
                                    random.shuffle(values2)

                                for j, val2 in enumerate(values2):
                                    val_ipaddr = val2[0]
                                    val_port = int(val2[1])
                                    val_proto = val2[2]
                                    scan = 1

                                    if self.proto == 'ALL' and self.rport == '5060-5061':
                                        if val_port == 5060 and val_proto == 'TLS':
                                            scan = 0
                                        elif val_port == 5061 and (val_proto == 'UDP' or val_proto == 'TCP'):
                                            scan = 0

                                    if scan == 1:
                                        if self.host != '' and self.domain == '':
                                            self.domain = self.host
                                        if self.domain == '':
                                            self.domain = val_ipaddr

                                        executor.submit(self.scan_host, val_ipaddr,
                                                        val_port, val_proto)
                    except KeyboardInterrupt:
                        print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
                        self.quit = True

                    values2.clear()
                    count = 0

        end = time.time()
        self.totaltime = int(end-start)

        self.found.sort()
        self.print()

    def scan_host(self, ipaddr, port, proto):
        if self.quit == False:
            print(self.c.BYELLOW + '[%s] Scanning %s:%d/%s'.ljust(100) %
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
                print(self.c.RED + 'Failed to create socket')
                return

            bind = '0.0.0.0'
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            if self.proxy == '':
                host = (str(ipaddr), port)
            else:
                if self.proxy.find(':') > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(':')
                else:
                    proxy_ip = self.proxy
                    proxy_port = '5060'

                host = (str(proxy_ip), int(proxy_port))

            domain = self.domain
            if domain == '':
                domain = ipaddr

            contact_domain = self.contact_domain
            if contact_domain == '':
                contact_domain = '10.0.0.1'

            fdomain = self.from_domain
            tdomain = self.to_domain

            if not self.from_domain or self.from_domain == '':
                fdomain = self.domain
            if not self.to_domain or self.to_domain == '':
                tdomain = self.domain

            if self.method == 'REGISTER':
                if self.to_user == '100' and self.from_user != '100':
                    self.to_user = self.from_user
                if self.to_user != '100' and self.from_user == '100':
                    self.from_user = self.to_user

            if self.proxy != '':
                self.route = '<sip:%s;lr>' % self.proxy

            msg = create_message(self.method, '', contact_domain, self.from_user, self.from_name, fdomain,
                                 self.to_user, self.to_name, tdomain, proto, domain, self.user_agent, lport, '', '', '', '1', '', '', 1, '', 0, '', self.route, self.ppi, self.pai, '', 1)

            try:
                sock.settimeout(2)

                if proto == 'TCP':
                    sock.connect(host)

                if proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.verbose == 2:
                    print(self.c.BWHITE + '[+] Sending to %s:%d/%s ...' %
                          (ipaddr, port, proto))
                    print(self.c.YELLOW + msg)

                rescode = '100'

                while rescode[:1] == '1':
                    # receive temporary code
                    if proto == 'TLS':
                        resp = sock_ssl.recv(4096)
                        (ip, rport) = host
                    else:
                        (resp, addr) = sock.recvfrom(4096)
                        (ip, rport) = addr

                    headers = parse_message(resp.decode())

                    if headers and headers['response_code'] != '':
                        response = '%s %s' % (
                            headers['response_code'], headers['response_text'])
                        rescode = headers['response_code']

                        if self.verbose == 2:
                            print(self.c.BWHITE + '[-] Receiving from %s:%s/%s ...' %
                                  (ipaddr, rport, proto))
                            print(self.c.GREEN + resp.decode() + self.c.WHITE)

                headers = parse_message(resp.decode())

                if headers and headers['response_code'] != '':
                    sip_type = headers['type']
                    if self.method == 'REGISTER':
                        if headers['response_code'] == '405':
                            sip_type = 'Device'
                        if headers['response_code'] == '401':
                            sip_type = 'Server'

                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    if self.fp == 1:
                        fps = fingerprinting(
                            self.method, resp.decode(), headers, self.verbose)
                        
                        fp = ''
                        for f in fps:
                            if f == '':
                                fp = '%s' % f
                            else:
                                fp += '/%s' % f
                    else:
                        fp = ''

                    if fp[0:1] == '/':
                        fp = fp[1:]

                    line = '%s###%d###%s###%s###%s###%s###%s' % (
                        ip, rport, proto, response, headers['ua'], sip_type, fp)
                    self.found.append(line)

                    if self.verbose == 1:
                        if headers['ua'] != '':
                            print(self.c.WHITE + 'Response <%s %s> from %s:%d/%s with User-Agent %s' %
                                  (headers['response_code'], headers['response_text'], ip, rport, proto, headers['ua']))
                        else:
                            print(self.c.WHITE + 'Response <%s %s> from %s:%d/%s without User-Agent' %
                                  (headers['response_code'], headers['response_text'], ip, rport, proto))
            except socket.timeout:
                pass
            except:
                pass
            finally:
                sock.close()

                if proto == 'TLS':
                    sock_ssl.close()

            return headers

    def print(self):
        iplen = len('IP address')
        polen = len('Port')
        prlen = len('Proto')
        relen = len('Response')
        ualen = len('User-Agent')
        tplen = len('Type')
        fplen = len('Fingerprinting')

        for x in self.found:
            (ip, port, proto, res, ua, type, fp) = x.split('###')
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
            tlen = iplen+polen+prlen+relen+ualen+tplen+fplen+20
        else:
            tlen = iplen+polen+prlen+relen+ualen+tplen+17

        print(self.c.WHITE + ' ' + '-' * tlen)
        if self.fp == 1:
            print(self.c.WHITE +
                  '| ' + self.c.BWHITE + 'IP address'.ljust(iplen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Port'.ljust(polen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Proto'.ljust(prlen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Response'.ljust(relen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'User-Agent'.ljust(ualen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Type'.ljust(tplen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Fingerprinting'.ljust(fplen) + self.c.WHITE + ' |')
        else:
            print(self.c.WHITE +
                  '| ' + self.c.BWHITE + 'IP address'.ljust(iplen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Port'.ljust(polen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Proto'.ljust(prlen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Response'.ljust(relen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'User-Agent'.ljust(ualen) + self.c.WHITE +
                  ' | ' + self.c.BWHITE + 'Type'.ljust(tplen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if self.ofile != '':
            f = open(self.ofile, 'a+')

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (ip, port, proto, res, ua, type, fp) = x.split('###')

                if self.fp == 1:
                    print(self.c.WHITE +
                          '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                          ' | ' + self.c.GREEN + '%s' % port.ljust(polen) + self.c.WHITE +
                          ' | ' + self.c.GREEN + '%s' % proto.ljust(prlen) + self.c.WHITE +
                          ' | ' + self.c.BLUE + '%s' % res.ljust(relen) + self.c.WHITE +
                          ' | ' + self.c.YELLOW + '%s' % ua.ljust(ualen) + self.c.WHITE +
                          ' | ' + self.c.CYAN + '%s' % type.ljust(tplen) + self.c.WHITE +
                          ' | ' + self.c.GREEN + '%s' % fp.ljust(fplen) + self.c.WHITE + ' |')

                    if self.ofile != '':
                        f.write('%s:%s/%s => %s - %s (%s)\n' %
                                (ip, port, proto, res, ua, fp))
                else:
                    print(self.c.WHITE +
                          '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                          ' | ' + self.c.GREEN + '%s' % port.ljust(polen) + self.c.WHITE +
                          ' | ' + self.c.GREEN + '%s' % proto.ljust(prlen) + self.c.WHITE +
                          ' | ' + self.c.BLUE + '%s' % res.ljust(relen) + self.c.WHITE +
                          ' | ' + self.c.YELLOW + '%s' % ua.ljust(ualen) + self.c.WHITE +
                          ' | ' + self.c.CYAN + '%s' % type.ljust(tplen) + self.c.WHITE + ' |')

                    if self.ofile != '':
                        f.write('%s:%s/%s => %s - %s\n' %
                                (ip, port, proto, res, ua))

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        print(self.c.BWHITE + 'Time elapsed: ' + self.c.YELLOW + '%s' %
              format_time(self.totaltime) + self.c.WHITE)
        print(self.c.WHITE)

        if self.fp == 1 and len(self.found) > 0:
            print(self.c.YELLOW +
                  '[!] Fingerprinting is based on `To-tag` and other header values. The result may not be correct' + self.c.WHITE)
            if self.method != 'REGISTER':
                print(self.c.YELLOW +
                      '[!] Tip: You can try -m REGISTER to verify the fingerprinting result' + self.c.WHITE)
            print(self.c.WHITE)

        if self.ofile != '':
            f.close()

        self.found.clear()
