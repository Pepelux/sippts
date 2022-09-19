#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.1.1'
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
from lib.color import Color
from itertools import product
from concurrent.futures import ThreadPoolExecutor


class SipScan:
    def __init__(self):
        self.ip = ''
        self.host = ''
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
        self.nocolor = ''
        self.ofile = ''

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False

        self.c = Color()

    # def __del__(self):
    #     print('SIPScan destruido')

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
        local_ip = get_machine_default_ip()

        # if rport is by default but we want to scan TLS protocol, also try with port 5061
        if self.rport == '5060' and (self.proto == 'TLS' or self.proto == 'ALL'):
            self.rport = '5060-5061'

        if self.rport.upper() == 'ALL':
            self.rport = '1-65536'

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
        if self.file != '':
            try:
                with open(self.file) as f:
                    line = f.readline()
                    line = line.replace('\n', '')

                    while(line):
                        if self.quit == False:
                            try:
                                ip = socket.gethostbyname(line)
                                self.ip = IP(ip)
                            except:
                                self.ip = IP(line)

                            ips = []
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
                                        print(self.c.YELLOW + '[+] Ping %s ...' %
                                            str(long2ip(i)) + self.c.WHITE, end='\r')

                                        if ping(long2ip(i), '0.1') == True:
                                            print(self.c.GREEN + '\n   [-] ... Pong %s' %
                                                str(long2ip(i)) + self.c.WHITE)
                                            ips.append(long2ip(i))

                            self.prepare_scan(ips, ports, protos)

                        line = f.readline()

                f.close()
            except:
                print('Error reading file %s' % self.file)
                exit()
        else:
            ips = []
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
                        print(self.c.YELLOW + '[+] Ping %s ...' %
                                str(long2ip(i)) + self.c.WHITE, end='\r')

                        if ping(long2ip(i), '0.1') == True:
                            print(self.c.GREEN + '\n   [-] ... Pong %s' %
                                    str(long2ip(i)) + self.c.WHITE)
                            ips.append(long2ip(i))

            self.prepare_scan(ips, ports, protos)


    def prepare_scan(self, ips, ports, protos):
        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(ips, ports, protos)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(self.c.BWHITE + '[!] IP/Network: ' +
              self.c.GREEN + '%s' % str(self.ip))

        print(self.c.BWHITE + '[!] Port range: ' +
              self.c.GREEN + '%s' % self.rport)
        if self.proto == 'ALL':
            print(self.c.BWHITE + '[!] Protocols: ' +
                  self.c.GREEN + 'UDP, TCP, TLS')
        else:
            print(self.c.BWHITE + '[!] Protocol: ' + self.c.GREEN + '%s' %
                  self.proto.upper())

        print(self.c.BWHITE + '[!] Method to scan: ' +
              self.c.GREEN + '%s' % self.method)

        if self.domain != '' and self.domain != str(self.ip) and self.domain != self.host:
            print(self.c.BWHITE + '[!] Customized Domain: ' +
                  self.c.GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(self.c.BWHITE + '[!] Customized Contact Domain: ' + self.c.GREEN + '%s' %
                  self.contact_domain)
        if self.from_name != '':
            print(self.c.BWHITE + '[!] Customized From Name: ' +
                  self.c.GREEN + '%s' % self.from_name)
        if self.from_user != '100':
            print(self.c.BWHITE + '[!] Customized From User: ' +
                  self.c.GREEN + '%s' % self.from_user)
        if self.from_domain != '':
            print(self.c.BWHITE + '[!] Customized From Domain: ' +
                  self.c.GREEN + '%s' % self.from_domain)
        if self.to_name != '':
            print(self.c.BWHITE + '[!] Customized To Name: ' +
                  self.c.GREEN + '%s' % self.to_name)
        if self.to_user != '100':
            print(self.c.BWHITE + '[!] Customized To User:' +
                  self.c.GREEN + ' %s' % self.to_user)
        if self.to_domain != '':
            print(self.c.BWHITE + '[!] Customized To Domain: ' +
                  self.c.GREEN + '%s' % self.to_domain)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[!] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)

        print(self.c.BWHITE + '[!] Used threads: ' +
              self.c.GREEN + '%d' % nthreads)
        if nthreads > 200:
            print(self.c.BRED +
                  '[x] More than 200 threads can cause socket problems')
        print(self.c.WHITE)

        if self.ofile != '':
            f = open(self.ofile, 'a+')

            f.write('[!] IP/Network: %s' % str(self.ip))
            f.write('\n')
            f.write('[!] Port range: %s' % self.rport)
            f.write('\n')
            if self.proto == 'ALL':
                f.write('[!] Protocols: UDP, TCP, TLS')
            else:
                f.write('[!] Protocol: %s' % self.proto.upper())
            f.write('\n')
            f.write('[!] Method to scan: %s' % self.method)
            f.write('\n\n')

            f.close()

        values = product(ips, ports, protos)

        try:
            with ThreadPoolExecutor(max_workers=nthreads) as executor:
                if self.quit == False:
                    for i, val in enumerate(values):
                        val_ipaddr = val[0]
                        val_port = int(val[1])
                        val_proto = val[2]

                        if self.host != '' and self.domain == '':
                            self.domain = self.host
                        if self.domain == '':
                            self.domain = val_ipaddr
                        if not self.from_domain or self.from_domain == '':
                            self.from_domain = self.domain
                        if not self.to_domain or self.to_domain == '':
                            self.to_domain = self.domain

                        executor.submit(self.scan_host, val_ipaddr,
                                        val_port, val_proto)
        except KeyboardInterrupt:
            print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
            self.quit = True

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
                                 self.to_user, self.to_name, self.to_domain, proto, domain, self.user_agent, lport, '', '', '', '1', '', '', 1, '', 0, '', '')

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
                    print(self.c.BWHITE + '[+] Sending to %s:%d/%s ...' %
                          (ipaddr, port, proto))
                    print(self.c.YELLOW + msg)

                if proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                    (ip, rport) = host
                else:
                    (resp, addr) = sock.recvfrom(4096)
                    (ip, rport) = addr

                if self.verbose == 2:
                    print(self.c.BWHITE + '[+] Receiving from %s:%d ...' %
                          (ip, rport))
                    print(self.c.GREEN + resp.decode())

                headers = parse_message(resp.decode())

                if headers:
                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    line = '%s###%d###%s###%s###%s###%s' % (
                        ip, rport, proto, response, headers['ua'], self.fingerprinting(headers['totag']))
                    self.found.append(line)

                    if self.verbose == 1:
                        if headers['ua'] != '':
                            print(self.c.WHITE + 'Response <%s %s> from %s:%d/%s with User-Agent %s' %
                                  (headers['response_code'], headers['response_text'], ip, rport, proto, headers['ua']))
                        else:
                            print(self.c.WHITE + 'Response <%s %s> from %s:%d/%s without User-Agent' %
                                  (headers['response_code'], headers['response_text'], ip, rport, proto))

                return headers
            except socket.timeout:
                pass
            except:
                pass
            finally:
                sock.close()

    def fingerprinting(self, tag):
        fingerprint = '-'

        m = re.search('^(as[0-9a-f]{8})', tag)
        if m:
            fingerprint += '/Asterisk PBX'
        m = re.search('([a-f0-9]{32}.[a-f0-9]{2,4})', tag)
        if m:
            fingerprint += '/Kamailio SIP Proxy'

        # m = re.search('([a-fA-F0-9]{16}i0)', tag)
        # if m:
        #     fingerprint += '/Sipura/Linksys SPA'
        # m = re.search('([a-fA-F0-9]{6,8}-[a-fA-F0-9]{2,4})', tag)
        # if m:
        #     fingerprint += '/Cisco VoIP Gateway'
        # m = re.search('([0-9]{5,10})', tag)
        # if m:
        #     fingerprint += '/Grandstream Phone or Gateway'
        # m = re.search('([a-f0-9]{8})', tag)
        # if m:
        #     fingerprint += '/Cisco IP Phone'

        if fingerprint[0:2] == '-/':
            fingerprint = fingerprint[2:]

        return fingerprint

    def print(self):
        iplen = len('IP address')
        polen = len('Port')
        prlen = len('Proto')
        relen = len('Response')
        ualen = len('User-Agent')
        fplen = len('Fingerprinting')

        for x in self.found:
            (ip, port, proto, res, ua, fp) = x.split('###')
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
            if len(fp) > fplen:
                fplen = len(fp)

        tlen = iplen+polen+prlen+relen+ualen+fplen+17
        
        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'IP address'.ljust(iplen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Port'.ljust(polen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Proto'.ljust(prlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Response'.ljust(relen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'User-Agent'.ljust(ualen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Fingerprinting'.ljust(fplen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if self.ofile != '':
            f = open(self.ofile, 'a+')

            f.write(' ' + '-' * tlen)
            f.write('\n')
            f.write('| IP address'.ljust(iplen) + 
                    ' | Port'.ljust(polen) + 
                    ' | Proto'.ljust(prlen) + 
                    ' | Response'.ljust(relen) + 
                    ' | User-Agent'.ljust(ualen) + 
                    ' | Fingerprinting'.ljust(fplen) + ' |')
            f.write('\n')
            f.write(' ' + '-' * tlen)
            f.write('\n')

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')

            if self.ofile != '':
                f.write('| Nothing found'.ljust(tlen-2) + ' |')
                f.write('\n')
        else:
            for x in self.found:
                (ip, port, proto, res, ua, fp) = x.split('###')

                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % port.ljust(polen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % proto.ljust(prlen) + self.c.WHITE +
                      ' | ' + self.c.BLUE + '%s' % res.ljust(relen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % ua.ljust(ualen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % fp.ljust(fplen) + self.c.WHITE + ' |')

                if self.ofile != '':
                        f.write('| %s' % ip.ljust(iplen) + 
                                ' | %s' % port.ljust(polen) + 
                                ' | %s' % proto.ljust(prlen) +
                                ' | %s' % res.ljust(relen) + 
                                ' | %s' % ua.ljust(ualen) + 
                                ' | %s' % fp.ljust(fplen) + ' |')
                        f.write('\n')

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        if self.ofile != '':
            f.write(' ' + '-' * tlen)
            f.write('\n\n')

            f.close()

        self.found.clear()
