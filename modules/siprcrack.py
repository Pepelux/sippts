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
import threading
import signal
from lib.functions import create_message, parse_message, parse_digest, ip2long, long2ip, generate_random_string, get_free_port, calculateHash
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


class SipRemoteCrack:
    def __init__(self):
        self.ip = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.exten = ''
        self.prefix = ''
        self.domain = ''
        self.contact_domain = ''
        self.wordlist = ''
        self.user_agent = 'pplsip'
        self.threads = '10'

        self.run = True

        self.ips = []
        self.extens = []

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0


    def register(self, ip, to_user, pwd):
        if self.run == True:
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

            host = (str(ip), int(self.rport))

            data = dict()

            msg = create_message('REGISTER', self.contact_domain, to_user, '',
                                 to_user, '', self.proto, self.domain, self.user_agent, lport, '', '', '', 1, '', '', '', 0)

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

                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    # Received the auth digest?
                    if headers['auth'] != '':
                        method = 'REGISTER'
                        auth = headers['auth']
                        callid = headers['callid']
                        data['ua'] = headers['ua']

                        headers = parse_digest(auth)
                        username = to_user
                        realm = headers['realm']
                        nonce = headers['nonce']
                        uri = 'sip:%s' % (self.domain)
                        algorithm = headers['algorithm']
                        cnonce = headers['cnonce']
                        nc = headers['nc']
                        qop = headers['qop']

                        if qop != '' and cnonce == '':
                            cnonce = generate_random_string(8, 0)
                        if qop != '' and nc == '':
                            nc = '00000001'

                        response = calculateHash(
                            username, realm, pwd, method, uri, nonce, algorithm, cnonce, nc, qop, 0, '')
                        digest = 'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=%s' % (
                            username, realm, nonce, uri, response, algorithm)
                        if qop != '':
                            digest += ', qop=%s' % qop
                        if cnonce != '':
                            digest += ', cnonce="%s"' % cnonce
                        if nc != '':
                            digest += ', nc=%s' % nc

                        msg = create_message('REGISTER', self.contact_domain, username, '',
                                             to_user, '', self.proto, self.domain, self.user_agent, lport, '', callid, '', 1, '', digest, '', 0)

                        if self.proto == 'TCP':
                            sock.connect(host)

                        if self.proto == 'TLS':
                            sock_ssl = ssl.wrap_socket(
                                sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                            sock_ssl.connect(host)
                            sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                        else:
                            sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                        if self.proto == 'TLS':
                            resp = sock_ssl.recv(4096)
                        else:
                            resp = sock.recv(4096)

                        headers = parse_message(resp.decode())
                        data['code'] = headers['response_code']
                        data['text'] = headers['response_text']

                return data
            except socket.timeout:
                pass
            except:
                pass
            finally:
                sock.close()

        return data

    def signal_handler(self, sig, frame):
        print(BYELLOW + 'You pressed Ctrl+C!')
        print(BWHITE + '\nStopping siprcrack ...')
        print(WHITE)

        self.stop()

    def stop(self):
        self.run = False

        for t in threading.enumerate():
            if t.name != 'MainThread':
                try:
                    t.join()
                except:
                    pass

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061
        
        # check protocol
        if self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # create a list of IP addresses
        self.ips = []
        hosts = list(ipaddress.ip_network(str(self.ip)).hosts())

        if hosts == []:
            hosts.append(self.ip)

        last = len(hosts)-1
        start_ip = hosts[0]
        end_ip = hosts[last]

        ipini = int(ip2long(str(start_ip)))
        ipend = int(ip2long(str(end_ip)))

        for i in range(ipini, ipend+1):
            self.ips.append(long2ip(i))

        # create a list of extens
        self.extens = []
        for p in self.exten.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    self.extens.append(x)
            else:
                self.extens.append(p)

        signal.signal(signal.SIGINT, self.signal_handler)
        print(BYELLOW + '\nPress Ctrl+C to stop\n')
        print(WHITE)

        threads = list()
        t = threading.Thread(target=self.crack, daemon=True)
        threads.append(t)
        t.start()

        t.join()

    def crack(self):
        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(self.ips, self.extens)))
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

        if self.domain != '':
            print(BWHITE + '[!] Customized Domain: ' +
                  GREEN + '%s' % self.domain)
        if self.contact_domain != '':
            print(BWHITE + '[!] Customized Contact Domain: ' + GREEN + '%s' %
                  self.contact_domain)
        if self.user_agent != 'pplsip':
            print(BWHITE + '[!] Customized User-Agent: ' +
                  GREEN + '%s' % self.user_agent)

        print(BWHITE+'[!] Total threads: ' + GREEN + '%d' % nthreads)
        print(BWHITE + '[!] Wordlist: ' + GREEN + '%s' % self.wordlist)
        print(WHITE)

        values = product(self.ips, self.extens)

        try:
            with ThreadPoolExecutor(max_workers=nthreads) as executor:
                if self.run == True:
                    for i, val in enumerate(values):
                        val_ipaddr = val[0]
                        val_exten = int(val[1])
                        to_user = '%s%s' % (self.prefix, val_exten)
                        if not self.domain or self.domain == '':
                            self.domain = val_ipaddr

                        executor.submit(self.scan_host, val_ipaddr, to_user)
        except:
            pass

        self.found.sort()
        self.print()

    def scan_host(self, ipaddr, to_user):
        data = dict()

        if self.run == True:
            with open(self.wordlist) as f:
                pwd = f.readline()
                pwd = pwd.replace('\n', '')
                pwd = pwd.replace('\'', '')
                pwd = pwd.replace('"', '')
                pwd = pwd.replace('<', '')
                pwd = pwd.replace('>', '')
                pwd = pwd.strip()
                pwd = pwd[0:50]

                if pwd != '':
                    while pwd and self.run == True:
                        print(BYELLOW+'[%s] Scanning %s:%s/%s => Exten/Pass: %s/%s'.ljust(150) %
                              (self.line[self.pos], ipaddr, self.rport, self.proto, to_user, pwd), end="\r")
                        self.pos += 1
                        if self.pos > 3:
                            self.pos = 0

                        if self.domain == '':
                            self.domain = ipaddr

                        if self.contact_domain == '':
                            self.contact_domain = '10.0.0.1'

                        data = self.register(ipaddr, to_user, pwd)
                        if data and data['code'] == '200':
                            print(WHITE)
                            pre = ''
                            print(BWHITE + '%s' % pre + WHITE+'Password for user ' + BBLUE + '%s' %
                                  to_user + WHITE + ' found: ' + BRED + '%s' % pwd + WHITE)
                            line = '%s###%s###%s###%s###%s' % (
                                ipaddr, self.rport, self.proto, to_user, pwd)
                            self.found.append(line)

                            f.close()
                            return

                        pwd = f.readline()
                        if pwd != '\n':
                            pwd = pwd.replace('\n', '')
                            pwd = pwd.replace('\'', '')
                            pwd = pwd.replace('"', '')
                            pwd = pwd.replace('<', '')
                            pwd = pwd.replace('>', '')
                            pwd = pwd.strip()
                            pwd = pwd[0:50]

        f.close()

    def print(self):
        iplen = len('IP address')
        polen = len('Port')
        prlen = len('Proto')
        uslen = len('User')
        pwlen = len('Password')

        for x in self.found:
            (ip, port, proto, user, pwd) = x.split('###')
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(user) > uslen:
                uslen = len(user)
            if len(pwd) > pwlen:
                pwlen = len(pwd)

        tlen = iplen+polen+prlen+uslen+pwlen+14
        print(WHITE + ' ' + '-' * tlen)
        print(WHITE +
              '| ' + BWHITE + 'IP address'.ljust(iplen) + WHITE +
              ' | ' + BWHITE + 'Port'.ljust(polen) + WHITE +
              ' | ' + BWHITE + 'Proto'.ljust(prlen) + WHITE +
              ' | ' + BWHITE + 'User'.ljust(uslen) + WHITE +
              ' | ' + BWHITE + 'Password'.ljust(pwlen) + WHITE + ' |')
        print(WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(WHITE + '| ' + WHITE + 'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (ip, port, proto, user, pwd) = x.split('###')

                print(WHITE +
                      '| ' + BGREEN + '%s' % ip.ljust(iplen) + WHITE +
                      ' | ' + GREEN + '%s' % port.ljust(polen) + WHITE +
                      ' | ' + GREEN + '%s' % proto.ljust(prlen) + WHITE +
                      ' | ' + BBLUE + '%s' % user.ljust(uslen) + WHITE +
                      ' | ' + BRED + '%s' % pwd.ljust(pwlen) + WHITE + ' |')

        print(WHITE + ' ' + '-' * tlen)
        print(WHITE)
