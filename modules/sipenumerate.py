#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ssl
import time
from lib.functions import create_message, get_free_port, parse_message, fingerprinting, format_time
from lib.color import Color
from lib.logos import Logo
from concurrent.futures import ThreadPoolExecutor


class SipEnumerate:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.proxy = ''
        self.route = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.from_name = ''
        self.from_domain = ''
        self.to_user = '100'
        self.to_name = ''
        self.to_domain = ''
        self.user_agent = 'pplsip'
        self.digest = ''
        self.verbose = '0'

        self.totaltime = 0
        self.quit = False

        self.found = []

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
                             'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']

        self.proto = self.proto.upper()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        logo = Logo('sipenumerate')
        logo.print()

        print(self.c.BWHITE + '[✓] IP address: ' + self.c.GREEN + '%s' % str(self.ip) + self.c.WHITE +
              ':' + self.c.GREEN + '%s' % self.rport + self.c.WHITE + '/' + self.c.GREEN + '%s' % self.proto)
        if self.proxy != '':
            print(self.c.BWHITE + '[✓] Outbound Proxy: ' + self.c.GREEN + '%s' %
                  self.proxy)
        if self.domain != '':
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

        print(self.c.WHITE)

        if self.host != '' and self.domain == '':
            self.domain = self.host
        if self.domain == '':
            self.domain = self.ip
        if not self.from_domain or self.from_domain == '':
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == '':
            self.to_domain = self.domain

        if self.contact_domain == '':
            self.contact_domain = '10.0.0.1'

        if self.proxy != '':
            self.route = '<sip:%s;lr>' % self.proxy

        start = time.time()

        with ThreadPoolExecutor(max_workers=20) as executor:
            for j, method in enumerate(supported_methods):
                if self.quit == False:
                    executor.submit(self.send, method)

        end = time.time()
        self.totaltime = int(end-start)

        self.print()

    def send(self, method):
        if self.quit == False:
            try:
                if self.proto == 'UDP':
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

            if self.proxy == '':
                host = (str(self.ip), int(self.rport))
            else:
                if self.proxy.find(':') > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(':')
                else:
                    proxy_ip = self.proxy
                    proxy_port = '5060'

                host = (str(proxy_ip), int(proxy_port))

            try:
                sock.settimeout(5)

                if self.proto == 'TCP':
                    sock.connect(host)

                if self.proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
            except:
                print('Socket connection error')
                exit()

            from_user = self.from_user
            to_user = self.to_user

            if method == 'REGISTER':
                if self.to_user == '100' and self.from_user != '100':
                    from_user = self.from_user
                    to_user = self.from_user
                if self.to_user != '100' and self.from_user == '100':
                    from_user = self.to_user
                    to_user = self.to_user

            msg = create_message(method, '', self.contact_domain, from_user, self.from_name, self.domain,
                                 to_user, self.to_name, self.domain, self.proto, self.domain, self.user_agent, lport, '', '', '', '1', '', self.digest, 1, '', 0, '', self.route, '', '', '')

            if self.verbose == 1:
                print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                      (self.ip, self.rport, self.proto))
                print(self.c.YELLOW + msg)

            try:
                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                rescode = '100'
                resdata = ''
                resdataua = ''

                while rescode[:1] == '1':
                    if self.proto == 'TLS':
                        resp = sock_ssl.recv(4096)
                    else:
                        resp = sock.recv(4096)

                    headers = parse_message(resp.decode())

                    if headers:
                        rescode = headers['response_code']
                        restext = headers['response_text']

                        ua = headers['ua']
                        if ua == '':
                            ua = 'Not found'

                        if resdata != '':
                            resdata = resdata + ' / '
                            resdataua = resdataua + self.c.WHITE + ' / '
                        resdata = resdata + '%s %s' % (rescode, restext)
                        resdataua = resdataua + self.c.YELLOW + \
                            '%s %s' % (rescode, restext) + \
                            self.c.WHITE + ' (User-Agent: %s)' % ua

                if self.verbose == 1:
                    print(self.c.BWHITE + '[+] Receiving from %s:%d ...' %
                          (self.ip, self.rport))
                    print(self.c.GREEN + resp.decode())
                else:
                    print(self.c.BCYAN + '%s' %
                          method + self.c.WHITE + ' => %s' % resdataua)

                fps = fingerprinting(method, resp.decode(),
                                     headers, self.verbose)

                fp = ''
                for f in fps:
                    if f == '':
                        fp = '%s' % f
                    else:
                        fp += '/%s' % f

                if fp[0:1] == '/':
                    fp = fp[1:]

                line = '%s###%s###%s###%s' % (
                    method, resdata, ua, fp)
                self.found.append(line)
            except KeyboardInterrupt:
                print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
                self.quit = True
            except socket.timeout:
                print(self.c.BGREEN + '%s' %
                      method + self.c.RED + ' => Timeout error')
                pass
            except:
                print(self.c.BGREEN + '%s' % method + self.c.RED + ' => Error')
                pass

            sock.close()

    def print(self):
        mlen = len('Method')
        rlen = len('Response')
        ualen = len('User-Agent')
        fplen = len('Fingerprinting')

        for x in self.found:
            (m, r, ua, fp) = x.split('###')
            if len(m) > mlen:
                mlen = len(m)
            if len(r) > rlen:
                rlen = len(r)
            if len(ua) > ualen:
                ualen = len(ua)
            if len(fp) > fplen:
                fplen = len(fp)

        tlen = mlen+rlen+ualen+fplen+11

        print(self.c.WHITE)
        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'Method'.ljust(mlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Response'.ljust(rlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'User-Agent'.ljust(ualen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Fingerprinting'.ljust(fplen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (m, r, ua, fp) = x.split('###')

                print(self.c.WHITE +
                      '| ' + self.c.BCYAN + '%s' % m.ljust(mlen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % r.ljust(rlen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % ua.ljust(ualen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % fp.ljust(fplen) + self.c.WHITE + ' |')

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        print(self.c.BWHITE + 'Time elapsed: ' + self.c.YELLOW + '%s' %
              format_time(self.totaltime) + self.c.WHITE)
        print(self.c.WHITE)

        if len(self.found) > 0:
            print(self.c.YELLOW +
                  '[!] Fingerprinting is based on `To-tag` and other header values. The result may not be correct\n' + self.c.WHITE)

        self.found.clear()
