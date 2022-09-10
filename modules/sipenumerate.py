#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from re import S
import socket
import sys
import ssl
from lib.functions import create_message, get_free_port, parse_message

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


class SipEnumerate:
    def __init__(self):
        self.ip = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.domain = ''
        self.contact_domain = ''
        self.from_user = '100'
        self.from_name = ''
        self.to_user = '100'
        self.to_name = ''
        self.user_agent = 'pplsip'
        self.digest = ''
        self.verbose = '0'

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
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        try:
            if self.proto == 'UDP':
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

        host = (str(self.ip), int(self.rport))

        if self.domain == '':
            self.domain = self.ip
        if self.contact_domain == '':
            self.contact_domain = '10.0.0.1'

        print(BWHITE + '[!] IP address: ' + GREEN + '%s' % str(self.ip) + WHITE +
              ':' + GREEN + '%s' % self.rport + WHITE + '/' + GREEN + '%s' % self.proto)
        print(WHITE)

        try:
            sock.settimeout(5)

            if self.proto == 'TCP':
                sock.connect(host)

            if self.proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                sock_ssl.connect(host)
        except:
            print('Socket connection error')
            exit()

        for method in supported_methods:
            msg = create_message(method, self.contact_domain, self.from_user, self.from_name, self.domain,
                                 self.to_user, self.to_name, self.domain, self.proto, self.domain, self.user_agent, lport, '', '', '', '1', '', self.digest, '', 0)


            if self.verbose == 1:
                print(BWHITE + '[+] Sending to %s:%s/%s ...' % (self.ip, self.rport, self.proto))
                print(YELLOW + msg)

            try:
                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                rescode = '100'
                resdata = ''

                while rescode[:1] == '1':
                    if self.proto == 'TLS':
                        resp = sock_ssl.recv(4096)
                    else:
                        resp = sock.recv(4096)

                    headers = parse_message(resp.decode())

                    if headers:
                        rescode = headers['response_code']
                        restext = headers['response_text']

                        if resdata != '':
                            resdata = resdata + WHITE + ' / '
                        resdata = resdata + YELLOW + \
                            '%s %s' % (rescode, restext)

                if self.verbose == 1:
                    print(BWHITE + '[+] Receiving from %s:%d ...' % (self.ip, self.rport))
                    print(GREEN + resp.decode())
                else:
                    print(BCYAN + '%s' % method + WHITE + ' => %s' % resdata)
            except socket.timeout:
                print(BGREEN + '%s' % method + RED + ' => Timeout error')
                pass
            except:
                print(BGREEN + '%s' % method + RED + ' => Error')
                pass

        print(WHITE)

        sock.close()
