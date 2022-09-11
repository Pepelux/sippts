#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ssl
from lib.functions import create_message, get_free_port
from lib.color import Color


class SipSend:
    def __init__(self):
        self.ip = ''
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
        self.user_agent = 'pplsip'
        self.digest = ''
        self.branch = ''
        self.callid = ''
        self.cseq = '1'
        self.sdp = 0
        self.nocolor = ''

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
                             'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        if self.nocolor == 1:
            self.c.ansy()

        if self.sdp == None:
            self.sdp = 0
        if self.cseq == None or self.cseq == '':
            self.cseq = '1'

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

        host = (str(self.ip), int(self.rport))

        if self.domain == '':
            self.domain = self.ip
        if self.from_domain == '':
            self.from_domain = self.ip
        if self.to_domain == '':
            self.to_domain = self.ip
        if self.contact_domain == '':
            self.contact_domain = '10.0.0.1'

        msg = create_message(self.method, self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                             self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, self.to_tag, self.digest, '', self.sdp)

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

            print(self.c.BWHITE + '[+] Sending to %s:%s ...' %
                  (self.ip, self.rport))
            print(self.c.YELLOW + msg + self.c.WHITE)

            if self.proto == 'TLS':
                resp = sock_ssl.recv(4096)
            else:
                resp = sock.recv(4096)

            print(self.c.BWHITE + '[+] Receiving from %s:%s ...' %
                  (self.ip, self.rport))
            print(self.c.GREEN + resp.decode() + self.c.WHITE)
        except socket.timeout:
            pass
        except:
            pass
        finally:
            sock.close()
