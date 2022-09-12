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
from lib.functions import create_message, get_free_port, parse_message, parse_digest, generate_random_string, calculateHash
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
        self.user = ''
        self.pwd = ''
        self.user_agent = 'pplsip'
        self.digest = ''
        self.branch = ''
        self.callid = ''
        self.cseq = '1'
        self.sdp = 0
        self.sdes = 0
        self.nocolor = ''

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
                             'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']

        self.method = self.method.upper()
        self.proto = self.proto.upper()

        if self.branch == '':
            self.branch = generate_random_string(71, 0)
        if self.callid == '':
            self.callid = generate_random_string(32, 1)
        if self.from_tag == '':
            self.from_tag = generate_random_string(8, 1)

        if self.nocolor == 1:
            self.c.ansy()

        if self.sdp == None:
            self.sdp = 0
        if self.sdes == 1:
            self.sdp = 2
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
                             self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, self.to_tag, self.digest, 1, '', self.sdp)

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

            print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                  (self.ip, self.rport, self.proto))
            print(self.c.YELLOW + msg + self.c.WHITE)

            rescode = '100'

            while rescode[:1] == '1':
                # receive temporary code
                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    rescode = headers['response_code']
                    print(self.c.BWHITE + '[+] Receiving from %s:%s/%s ...' %
                        (self.ip, self.rport, self.proto))
                    print(self.c.GREEN + resp.decode() + self.c.WHITE)

                    totag = headers['totag']

            if self.user != '' and self.pwd != '' and (headers['response_code'] == '401' or headers['response_code'] == '407'):
                # send ACK
                print(self.c.BWHITE + '[+] Request ACK')
                msg = create_message('ACK', self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                        self.to_user, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, totag, '', 1, '', 0)

                print(self.c.YELLOW + msg)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if headers['auth'] != '':
                    auth = headers['auth']
                    auth_type = headers['auth-type']
                    headers = parse_digest(auth)
                    realm = headers['realm']
                    nonce = headers['nonce']
                    uri = 'sip:%s@%s' % (self.to_user, self.domain)
                    algorithm = headers['algorithm']
                    cnonce = headers['cnonce']
                    nc = headers['nc']
                    qop = headers['qop']

                    if qop != '' and cnonce == '':
                        cnonce = generate_random_string(8, 0)
                    if qop != '' and nc == '':
                        nc = '00000001'

                    response = calculateHash(
                        self.user, realm, self.pwd, self.method, uri, nonce, algorithm, cnonce, nc, qop, 0, '')

                    digest = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s' % (
                        self.user, realm, nonce, uri, response, algorithm)
                    if qop != '':
                        digest += ', qop=%s' % qop
                    if cnonce != '':
                        digest += ', cnonce="%s"' % cnonce
                    if nc != '':
                        digest += ', nc=%s' % nc

                    self.branch = generate_random_string(71, 0)
                    self.cseq = str(int(self.cseq) + 1)

                    msg = create_message(self.method, self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                                        self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, self.to_tag, digest, auth_type, '', self.sdp)

                    try:
                        if self.proto == 'TLS':
                            sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                        else:
                            sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                        print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                            (self.ip, self.rport, self.proto))
                        print(self.c.YELLOW + msg + self.c.WHITE)

                        rescode = '100'

                        while rescode[:1] == '1':
                            # receive temporary code
                            if self.proto == 'TLS':
                                resp = sock_ssl.recv(4096)
                            else:
                                resp = sock.recv(4096)

                            headers = parse_message(resp.decode())

                            if headers:
                                response = '%s %s' % (
                                    headers['response_code'], headers['response_text'])
                                rescode = headers['response_code']
                                print(self.c.BWHITE + '[+] Receiving from %s:%s/%s ...' %
                                    (self.ip, self.rport, self.proto))
                                print(self.c.GREEN + resp.decode() + self.c.WHITE)
                    except:
                        print(self.c.NORMAL)

        except socket.timeout:
            pass
        except:
            pass
        finally:
            sock.close()
