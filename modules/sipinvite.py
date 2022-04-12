#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.0.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

# SipINVITE                     SIP Server                      Phone1              Phone2
#          ---> INVITE       --->
#                                         ---> INVITE      --->
#                                         <--- 100 Trying  <---
#          <--- 100 Trying   <---
#                                         <--- 180 Ringing <---
#          <--- 180 Ringing  <---
#                                         <--- 200 Ok      <---
#          <--- 200 Ok       <---
#          ---> ACK          --->
#          <--- 200 Ok       <---
#          ---> REFER phone2 --->
#                                         --->           INVITE                --->
#          <--- 202 Accept   <---
#                                                             <--->  RTP Session <--->
#                                                               (Phone 1 && phone 2)

__author__ = 'Jose Luis Verdeguer <verdeguer@zoonsuite.com>'
__version__ = '3.0.0'

import socket
import sys
import ipaddress
import ssl
from lib.functions import create_message, create_response_ok, parse_message, generate_random_string, get_machine_default_ip, parse_digest, calculateHash, get_free_port

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


class SipInvite:
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
        self.transfer = ''
        self.verbose = '0'
        self.auth_user = ''
        self.auth_pwd = ''

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        # check protocol
        if self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # my IP address
        local_ip = get_machine_default_ip()

        self.ip = str(self.ip)

        # SIP headers
        if self.domain == '':
            self.domain = self.ip
        if self.contact_domain == '':
            self.contact_domain = local_ip
        if self.auth_user != '':
            self.from_user = self.auth_user

        print(BWHITE + '[!] Target: ' + YELLOW + '%s' % self.ip + WHITE + ':' +
              YELLOW + '%s' % self.rport + WHITE + '/' + YELLOW + '%s' % self.proto)
        print(BWHITE + '[!] Call From: ' + YELLOW + '%s' % self.from_user)
        print(BWHITE + '[!] Call To: ' + YELLOW + '%s' % self.to_user)
        print(WHITE)

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

        host = (self.ip, int(self.rport))

        branch = generate_random_string(71, 0)
        callid = generate_random_string(32, 1)
        tag = generate_random_string(8, 1)

        msg = create_message('INVITE', self.contact_domain, self.from_user, self.from_name,
                             self.to_user, self.to_name, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, 1, '', '', '', 1)

        print(YELLOW + '[+] Request INVITE')
        if self.verbose == 1:
            print(WHITE + msg)

        try:
            sock.settimeout(15)

            # send INVITE
            if self.proto == 'TCP':
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
                resp = sock.recv(4096)

                headers = parse_message(resp.decode())

                if headers:
                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    rescode = headers['response_code']
                    print(BWHITE + '[-] Response %s' % response)
                    if self.verbose == 1:
                        print(WHITE + resp.decode())

                    totag = headers['totag']

            # receive 401/407 Unauthorized
            if self.auth_user != '' and self.auth_pwd != '' and (headers['response_code'] == '401' or headers['response_code'] == '407'):
                # send INVITE with Digest
                totag = ''
                branch = generate_random_string(71, 0)

                if headers['auth'] != '':
                    auth = headers['auth']
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
                        self.auth_user, realm, self.auth_pwd, 'INVITE', uri, nonce, algorithm, cnonce, nc, qop, self.verbose, '')
                    digest = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s' % (
                        self.auth_user, realm, nonce, uri, response, algorithm)
                    if qop != '':
                        digest += ', qop=%s' % qop
                    if cnonce != '':
                        digest += ', cnonce="%s"' % cnonce
                    if nc != '':
                        digest += ', nc=%s' % nc

                    print(BYELLOW + '[+] Request INVITE')
                    msg = create_message('INVITE', self. contact_domain, self.from_user, self.from_name,
                                         self.to_user, self.to_name, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, 2, totag, local_ip, digest, '', 1)

                    if self.verbose == 1:
                        print(WHITE + msg)

                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                    # receive response
                    headers = parse_message(resp.decode())

                    if headers:
                        response = '%s %s' % (
                            headers['response_code'], headers['response_text'])
                        rescode = headers['response_code']
                        print(BYELLOW + '[-] Response %s' % response)
                        if self.verbose == 1:
                            print(WHITE + resp.decode())

                    rescode = '100'

                    while rescode[:1] == '1':
                        # receive temporary code
                        resp = sock.recv(4096)

                        headers = parse_message(resp.decode())

                        if headers:
                            response = '%s %s' % (
                                headers['response_code'], headers['response_text'])
                            rescode = headers['response_code']
                            print(BYELLOW + '[-] Response %s' % response)
                            if self.verbose == 1:
                                print(WHITE + resp.decode())

                            totag = headers['totag']

            # receive 200 Ok - call answered
            if headers['response_code'] == '200':
                # send ACK
                print(YELLOW + '[+] Request ACK')
                msg = create_message('ACK', self.contact_domain, self.from_user, self.from_name,
                                     self.to_user, self.to_name, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, 2, totag, local_ip, '', '', 0)

                if self.verbose == 1:
                    print(WHITE + msg)

                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.transfer != '':
                    # send REFER
                    print(YELLOW + '[+] Request REFER')
                    msg = create_message('REFER', self.contact_domain, self.from_user, self.from_name,
                                         self.to_user, self.to_name, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, 3, totag, local_ip, '', self.transfer, 0)

                    if self.verbose == 1:
                        print(WHITE + msg)

                    sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                    # receive response
                    headers = parse_message(resp.decode())

                    if headers:
                        response = '%s %s' % (
                            headers['response_code'], headers['response_text'])
                        rescode = headers['response_code']
                        print(YELLOW + '[-] Response %s' % response)
                        if self.verbose == 1:
                            print(WHITE + resp.decode())

                bye = ''

                while bye == '':
                    # wait bor BYE
                    resp = sock.recv(4096)

                    try:
                        headers = parse_message(resp.decode())
                        bye = headers['method']
                        print(BWHITE + '[-] Response %s' % bye)
                        if self.verbose == 1:
                            print(WHITE + resp.decode())
                    except:
                        pass

                # send 200 Ok
                cseq = headers['cseq']
                msg = create_response_ok(self.from_user, self.to_user, self.proto, self.domain, lport, int(
                    cseq), branch, callid, tag, totag)

                print(YELLOW+'[+] Sending 200 Ok\n')
                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                if self.verbose == 1:
                    print(WHITE + msg)
        except socket.timeout:
            pass
        except:
            pass
        finally:
            sock.close()

        return
