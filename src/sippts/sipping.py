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
import signal
from .lib.functions import create_message, get_free_port, parse_message, generate_random_string, get_machine_default_ip
from .lib.color import Color
from .lib.logos import Logo
from datetime import datetime


class SipPing:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.proxy = ''
        self.route = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.method = ''
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.from_name = ''
        self.from_domain = ''
        self.from_tag = ''
        self.to_user = '100'
        self.to_name = ''
        self.to_domain = ''
        self.to_tag = ''
        self.user = ''
        self.pwd = ''
        self.user_agent = 'pplsip'
        self.digest = ''
        self.branch = ''
        self.callid = ''
        self.cseq = '1'
        self.localip = ''
        self.number = 0
        self.interval = 1
        self.ppi = ''
        self.pai = ''

        self.run = True

        self.pingcount = 0

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
                             'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']

        if self.number == 0:
            self.number = 99999

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        # my IP address
        local_ip = self.localip
        if self.localip == '':
            local_ip = get_machine_default_ip()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061

        # check method
        if self.method not in supported_methods:
            print(self.c.BRED + 'Method %s is not supported' % self.method)
            sys.exit()

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        logo = Logo('sipping')
        logo.print()

        print(self.c.BWHITE + '[✓] Target: ' + self.c.YELLOW + '%s' % self.ip + self.c.WHITE + ':' +
              self.c.YELLOW + '%s' % self.rport + self.c.WHITE + '/' + self.c.YELLOW + '%s' % self.proto)
        if self.proxy != '':
            print(self.c.BWHITE + '[✓] Outbound Proxy: ' + self.c.GREEN + '%s' %
                  self.proxy)
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
        if self.from_tag != '':
            print(self.c.BWHITE + '[✓] Customized From Tag: ' +
                  self.c.GREEN + '%s' % self.from_tag)
        if self.to_name != '':
            print(self.c.BWHITE + '[✓] Customized To Name: ' +
                  self.c.GREEN + '%s' % self.to_name)
        if self.to_user != '100':
            print(self.c.BWHITE + '[✓] Customized To User: ' +
                  self.c.GREEN + '%s' % self.to_user)
        if self.to_domain != '':
            print(self.c.BWHITE + '[✓] Customized To Domain: ' +
                  self.c.GREEN + '%s' % self.to_domain)
        if self.to_tag != '':
            print(self.c.BWHITE + '[✓] Customized To Tag: ' +
                  self.c.GREEN + '%s' % self.to_tag)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[✓] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)
        print(self.c.WHITE)

        signal.signal(signal.SIGINT, self.signal_handler)
        print(self.c.BYELLOW + 'Press Ctrl+C to stop')
        print(self.c.WHITE)

        if self.branch == '':
            self.branch = generate_random_string(71, 71, 'ascii')
        if self.callid == '':
            self.callid = generate_random_string(32, 32, 'hex')
        if self.from_tag == '':
            self.from_tag = generate_random_string(8, 8, 'hex')

        if self.cseq == None or self.cseq == '':
            self.cseq = '1'

        if self.host != '' and self.domain == '':
            self.domain = self.host
        if self.domain == '':
            self.domain = self.ip
        if not self.from_domain or self.from_domain == '':
            self.from_domain = self.domain
        if not self.to_domain or self.to_domain == '':
            self.to_domain = self.domain

        if self.contact_domain == '':
            self.contact_domain = local_ip

        if self.proxy != '':
            self.route = '<sip:%s;lr>' % self.proxy

        ip = self.ip
        try:
            ip = socket.gethostbyname(self.ip)
        except:
            pass

        if ip != self.ip:
            print(self.c.YELLOW + 'PING ' + self.c.BGREEN + '%s (%s)' %
                  (self.ip, ip) + self.c.YELLOW + ' using method %s' % self.method)
        else:
            print(self.c.YELLOW + 'PING ' + self.c.BGREEN + '%s' %
                  self.ip + self.c.YELLOW + ' using method %s' % self.method)

        while self.run == True and self.pingcount < self.number:
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

            msg = create_message(self.method, '', self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                                 self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, self.to_tag, self.digest, 1, '', 0, '', self.route, self.ppi, self.pai, '', 1)

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
                sock.settimeout(2)

                if self.proto == 'TCP':
                    sock.connect(host)

                if self.proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
            except socket.timeout:
                print(self.c.RED +
                      '[!] Socket connection timeout' + self.c.WHITE)
                # sys.exit()
            except:
                print(self.c.RED +
                      '[!] Socket connection error' + self.c.WHITE)
                # sys.exit()

            try:
                start = time.time()

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])

                end = time.time()
                totaltime = end - start

                self.pingcount += 1
                print(self.c.CYAN + '[%s UTC] ' % datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + self.c.GREEN + '%s ' % response + self.c.WHITE + 'from ' + self.c.YELLOW + '%s' % ip + self.c.WHITE + ' cseq=' +
                      self.c.YELLOW + '%d' % self.pingcount + self.c.WHITE + ' time=' + self.c.YELLOW + '%fms' % totaltime + self.c.WHITE)
            except socket.timeout:
                self.pingcount += 1
                print(self.c.CYAN + '[%s UTC] ' % datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + self.c.WHITE + 'From ' + self.c.YELLOW + '%s' % ip + self.c.WHITE + ' cseq=' + self.c.YELLOW +
                      '%d' % self.pingcount + self.c.WHITE + ' Destination Host Unreachable' + self.c.WHITE)
                pass
            except KeyboardInterrupt:
                print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
                sys.exit()
            except:
                self.pingcount += 1
                print(self.c.CYAN + '[%s UTC] ' % datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + self.c.WHITE + 'From ' + self.c.YELLOW + '%s' % ip + self.c.WHITE + ' cseq=' + self.c.YELLOW +
                      '%d' % self.pingcount + self.c.WHITE + ' Destination Host Unreachable' + self.c.WHITE)
                pass

            time.sleep(self.interval)

        sock.close()

    def signal_handler(self, sig, frame):
        self.stop()

    def stop(self):
        self.run = False
        print(self.c.WHITE)
