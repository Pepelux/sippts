#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import socket
import sys
import ssl
from lib.functions import create_message, get_free_port, parse_message, parse_digest, generate_random_string, calculateHash, get_machine_default_ip
from lib.color import Color
from lib.logos import Logo


class SipSend:
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
        self.localip = ''
        self.nocolor = ''
        self.ofile = ''

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']
        supported_methods = ['REGISTER', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'MESSAGE', 'INVITE',
                             'OPTIONS', 'ACK', 'CANCEL', 'BYE', 'PRACK', 'INFO', 'REFER', 'UPDATE']

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

        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket')
            sys.exit(1)

        logo = Logo('sipsend')
        logo.print()

        print(self.c.BWHITE + '[✓] Target: ' + self.c.YELLOW + '%s' % self.ip + self.c.WHITE + ':' +
              self.c.YELLOW + '%s' % self.rport + self.c.WHITE + '/' + self.c.YELLOW + '%s' % self.proto)
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
        print(self.c.BWHITE + '[✓] Call From: ' +
              self.c.YELLOW + '%s' % self.from_user)
        print(self.c.BWHITE + '[✓] Call To: ' +
              self.c.YELLOW + '%s' % self.to_user)
        print(self.c.WHITE)

        if self.ofile != '':
            fw = open(self.ofile, 'w')

            fw.write('[✓] Target: %s:%s/%s\n' %
                     (self.ip, self.rport, self.proto))
            if self.domain != '' and self.domain != str(self.ip) and self.domain != self.host:
                fw.write('[✓] Customized Domain: %s\n' % self.domain)
            if self.contact_domain != '':
                fw.write('[✓] Customized Contact Domain: %s\n' %
                         self.contact_domain)
            if self.from_name != '':
                fw.write('[✓] Customized From Name: %s\n' % self.from_name)
            if self.from_user != '100':
                fw.write('[✓] Customized From User: %s\n' % self.from_user)
            if self.from_domain != '':
                fw.write('[✓] Customized From Domain: %s\n' % self.from_domain)
            if self.from_tag != '':
                fw.write('[✓] Customized From Tag: %s\n' % self.from_tag)
            if self.to_name != '':
                fw.write('[✓] Customized To Name: %s\n' % self.to_name)
            if self.to_user != '100':
                fw.write('[✓] Customized To User: %s\n' % self.to_user)
            if self.to_domain != '':
                fw.write('[✓] Customized To Domain: %s\n' % self.to_domain)
            if self.to_tag != '':
                fw.write('[✓] Customized To Tag: %s\n' % self.to_tag)
            if self.user_agent != 'pplsip':
                fw.write('[✓] Customized User-Agent: %s\n' % self.user_agent)
            fw.write('\n')

        if self.branch == '':
            self.branch = generate_random_string(71, 71, 'ascii')
        if self.callid == '':
            self.callid = generate_random_string(32, 32, 'hex')
        if self.from_tag == '':
            self.from_tag = generate_random_string(8, 8, 'hex')

        if self.nocolor == 1:
            self.c.ansy()

        if self.sdp == None:
            self.sdp = 0
        if self.sdes == 1:
            self.sdp = 2
        if self.cseq == None or self.cseq == '':
            self.cseq = '1'

        bind = '0.0.0.0'
        lport = get_free_port()

        try:
            sock.bind((bind, lport))
        except:
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
            self.contact_domain = local_ip

        msg = create_message(self.method, self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                             self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, self.to_tag, self.digest, 1, '', self.sdp, '', '')

        try:
            sock.settimeout(5)

            if self.proto == 'TCP':
                sock.connect(host)

            if self.proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)
                sock_ssl.connect(host)
                sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
            else:
                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

            print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                  (self.ip, self.rport, self.proto))
            print(self.c.YELLOW + msg + self.c.WHITE)

            if self.ofile != '':
                fw.write('[+] Sending to %s:%s/%s ...\n' %
                         (self.ip, self.rport, self.proto))
                fw.write(msg + '\n')

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

                    response = '%s %s' % (
                        headers['response_code'], headers['response_text'])
                    rescode = headers['response_code']
                    print(self.c.BWHITE + '[-] Receiving from %s:%s/%s ...' %
                          (self.ip, self.rport, self.proto))
                    print(self.c.GREEN + resp.decode() + self.c.WHITE)

                    if self.ofile != '':
                        fw.write('[-] Receiving from %s:%s/%s ...\n' %
                                 (self.ip, self.rport, self.proto))
                        fw.write(resp.decode() + '\n')

                    totag = headers['totag']

            if self.user != '' and self.pwd != '' and (headers['response_code'] == '401' or headers['response_code'] == '407'):
                # send ACK
                print(self.c.BWHITE + '[+] Request ACK')
                msg = create_message('ACK', self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                     self.to_user, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, totag, '', 1, '', 0, via, '')

                print(self.c.YELLOW + msg)

                if self.ofile != '':
                    fw.write('[+] Request ACK\n')
                    fw.write(msg + '\n')

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
                        self.user, realm, self.pwd, self.method, uri, nonce, algorithm, cnonce, nc, qop, 0, '')

                    digest = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s' % (
                        self.user, realm, nonce, uri, response, algorithm)
                    if qop != '':
                        digest += ', qop=%s' % qop
                    if cnonce != '':
                        digest += ', cnonce="%s"' % cnonce
                    if nc != '':
                        digest += ', nc=%s' % nc

                    self.branch = generate_random_string(71, 71, 'ascii')
                    self.cseq = str(int(self.cseq) + 1)

                    msg = create_message(self.method, self.contact_domain, self.from_user, self.from_name, self.from_domain, self.to_user, self.to_name, self.to_domain, self.proto,
                                         self.domain, self.user_agent, lport, self.branch, self.callid, self.from_tag, self.cseq, self.to_tag, digest, auth_type, '', self.sdp, via, '')

                    try:
                        if self.proto == 'TLS':
                            sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                        else:
                            sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                        # Send AUTH
                        print(self.c.BWHITE + '[+] Sending to %s:%s/%s ...' %
                              (self.ip, self.rport, self.proto))
                        print(self.c.YELLOW + msg + self.c.WHITE)

                        if self.ofile != '':
                            fw.write('[+] Sending to %s:%s/%s ...\n' %
                                     (self.ip, self.rport, self.proto))
                            fw.write(msg + '\n')

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
                                print(self.c.BWHITE + '[-] Receiving from %s:%s/%s ...' %
                                      (self.ip, self.rport, self.proto))
                                print(self.c.GREEN +
                                      resp.decode() + self.c.WHITE)

                                if self.ofile != '':
                                    fw.write('[-] Receiving from %s:%s/%s ...\n' %
                                             (self.ip, self.rport, self.proto))
                                    fw.write(resp.decode() + '\n')
                    except:
                        print(self.c.NORMAL)

        except socket.timeout:
            pass
        except:
            print(self.c.RED + '[!] Socket connection error\n' + self.c.WHITE)
            pass
        finally:
            sock.close()

        if self.ofile != '':
            fw.close()
