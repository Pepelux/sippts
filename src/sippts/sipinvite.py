#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
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

import socket
import sys
import ssl
import re
from concurrent.futures import ThreadPoolExecutor
from itertools import product
from .lib.functions import create_message, create_response_ok, parse_message, generate_random_string, get_machine_default_ip, parse_digest, calculateHash, get_free_port
from .lib.color import Color
from .lib.logos import Logo


class SipInvite:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.proxy = ''
        self.route = ''
        self.rport = '5060'
        self.lport = ''
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
        self.localip = ''
        self.transfer = ''
        self.verbose = '0'
        self.auth_user = ''
        self.auth_pwd = ''
        self.nosdp = 0
        self.sdes = 0
        self.nocolor = ''
        self.ofile = ''
        self.threads = '100'
        self.ppi = ''
        self.pai = ''

        self.sdp = 1

        self.quit = False

        self.c = Color()

    def invite(self, fw, src, dst):
        if self.quit == False:
            try:
                if self.proto == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(self.c.RED+'Failed to create socket')
                sys.exit(1)

            bind = '0.0.0.0'

            if self.lport == '' or self.lport == None:
                try:
                    # First try
                    lport = get_free_port()
                    sock.bind((bind, lport))
                except:
                    # Second try
                    lport = get_free_port()
                    sock.bind((bind, lport))
            else:
                lport = self.lport
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

            branch = generate_random_string(71, 71, 'ascii')
            callid = generate_random_string(32, 32, 'hex')
            tag = generate_random_string(8, 8, 'hex')

            msg = create_message('INVITE', self.localip, self.contact_domain, src, self.from_name, self.from_domain,
                                 dst, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, '1', '', '', 1, '', self.sdp, '', self.route, self.ppi, self.pai, '', 1)

            print(self.c.YELLOW +
                  '[=>] Request INVITE from %s to %s' % (src, dst))
            if self.verbose == 1 and self.ofile == '':
                print(self.c.YELLOW + msg)

            if self.ofile != '':
                fw.write('[=>] Request INVITE from %s to %s\n' % (src, dst))
                if self.verbose == 1:
                    fw.write(msg + '\n')

            sock.settimeout(15)

            if self.proto == 'TCP':
                sock.connect(host)

            if self.proto == 'TLS':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.load_default_certs()

                sock_ssl = context.wrap_socket(sock, server_hostname=str(host[0]))
                sock_ssl.connect(host)

            try:
                # send INVITE
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
                        via = headers['via']

                        response = '%s %s' % (
                            headers['response_code'], headers['response_text'])
                        rescode = headers['response_code']
                        print(
                            self.c.CYAN + '[<=] Response from %s to %s: ' % (dst, src) + self.c.CYAN + '%s' % response)

                        if self.verbose == 1 and self.ofile == '':
                            print(self.c.GREEN + resp.decode())

                        if self.ofile != '':
                            fw.write('[-] Response from %s to %s: %s\n' %
                                     (dst, src, response))
                            if self.verbose == 1:
                                fw.write(resp.decode() + '\n')

                        totag = headers['totag']

                # receive 401/407 Unauthorized
                if self.auth_user != '' and self.auth_pwd != '' and (headers['response_code'] == '401' or headers['response_code'] == '407'):
                    # send ACK
                    print(self.c.YELLOW +
                          '[=>] Request ACK from %s to %s' % (src, dst))
                    msg = create_message('ACK', self.localip, self.contact_domain, src, self.from_name, self.from_domain,
                                         dst, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, '1', totag, '', 1, '', 0, via, self.route, '', '', '', 1)

                    if self.verbose == 1 and self.ofile == '':
                        print(self.c.YELLOW + msg)

                    if self.ofile != '':
                        fw.write('[=>] Request ACK from %s to %s\n' %
                                 (src, dst))
                        if self.verbose == 1:
                            fw.write(msg + '\n')

                    if self.proto == 'TLS':
                        sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                    else:
                        sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                    # send INVITE with Digest
                    totag = ''
                    branch = generate_random_string(71, 71, 'ascii')

                    if headers['auth'] != '':
                        method = 'INVITE'
                        auth = headers['auth']
                        auth_type = headers['auth-type']
                        headers = parse_digest(auth)
                        realm = headers['realm']
                        nonce = headers['nonce']
                        uri = 'sip:%s@%s' % (dst, self.domain)
                        algorithm = headers['algorithm']
                        cnonce = headers['cnonce']
                        nc = headers['nc']
                        qop = headers['qop']

                        if qop != '' and cnonce == '':
                            cnonce = generate_random_string(8, 8, 'ascii')
                        if qop != '' and nc == '':
                            nc = '00000001'

                        response = calculateHash(
                            self.auth_user, realm, self.auth_pwd, method, uri, nonce, algorithm, cnonce, nc, qop, self.verbose, '')
                        digest = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=%s' % (
                            self.auth_user, realm, nonce, uri, response, algorithm)
                        if qop != '':
                            digest += ', qop=%s' % qop
                        if cnonce != '':
                            digest += ', cnonce="%s"' % cnonce
                        if nc != '':
                            digest += ', nc=%s' % nc

                        print(self.c.YELLOW +
                              '[=>] Request INVITE from %s to %s' % (src, dst))
                        msg = create_message('INVITE', self.localip, self.contact_domain, src, self.from_name, self.from_domain,
                                             dst, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, '2', totag, digest, auth_type, '', self.sdp, via, self.route, self.ppi, self.pai, '', 1)

                        if self.verbose == 1 and self.ofile == '':
                            print(self.c.YELLOW + msg)

                        if self.ofile != '':
                            fw.write(
                                '[=>] Request INVITE from %s to %s\n' % (src, dst))
                            if self.verbose == 1:
                                fw.write(msg + '\n')

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
                                response = '%s %s' % (
                                    headers['response_code'], headers['response_text'])
                                rescode = headers['response_code']
                                print(
                                    self.c.CYAN + '[<=] Response from %s to %s: %s' % (dst, src, response))
                                if self.verbose == 1 and self.ofile == '':
                                    print(self.c.GREEN + resp.decode())

                                if self.ofile != '':
                                    fw.write(
                                        '[<=] Response from %s to %s: %s\n' % (dst, src, response))
                                    if self.verbose == 1:
                                        fw.write(resp.code() + '\n')

                                totag = headers['totag']

                # receive 200 Ok - call answered
                if headers['response_code'] == '200':
                    # send ACK
                    print(self.c.YELLOW +
                          '[=>] Request ACK from %s to %s' % (src, dst))
                    msg = create_message('ACK', self.localip, self.contact_domain, src, self.from_name, self.from_domain,
                                         dst, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, '2', totag, digest, auth_type, '', 0, via, self.route, '', '', '', 1)

                    if self.verbose == 1 and self.ofile == '':
                        print(self.c.YELLOW + msg)

                    if self.ofile != '':
                        fw.write('[=>] Request ACK from %s to %s\n' %
                                 (src, dst))
                        if self.verbose == 1:
                            fw.write(msg + '\n')

                    if self.proto == 'TLS':
                        sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                    else:
                        sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                    if self.transfer != '':
                        # send REFER
                        print(self.c.YELLOW +
                              '[=>] Request REFERfrom %s  to %s' % (src, dst))
                        msg = create_message('REFER', self.localip, self.contact_domain, src, self.from_name, self.from_domain,
                                             dst, self.to_name, self.to_domain, self.proto, self.domain, self.user_agent, lport, branch, callid, tag, '3', totag, '', 1, self.transfer, 0, '', '', '', '', 1)

                        if self.verbose == 1 and self.ofile == '':
                            print(self.c.YELLOW + msg)

                        if self.ofile != '':
                            fw.write(
                                '[=>] Request REFER from %s to %s\n' % (src, dst))
                            if self.verbose == 1:
                                fw.write(msg + '\n')

                        if self.proto == 'TLS':
                            sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                        else:
                            sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                        # receive response
                        headers = parse_message(resp.decode())

                        if headers:
                            response = '%s %s' % (
                                headers['response_code'], headers['response_text'])
                            rescode = headers['response_code']
                            print(
                                self.c.CYAN + '[<=] Response from %s to %s: %s' % (dst, src, response))
                            if self.verbose == 1 and self.ofile == '':
                                print(self.c.GREEN + resp.decode())

                            if self.ofile != '':
                                fw.write('[<=] Response from %s to %s: %s\n' %
                                         (dst, src, response))
                                if self.verbose == 1:
                                    fw.write(resp.decode() + '\n')

                    bye = ''

                    while bye == '':
                        # wait bor BYE
                        if self.proto == 'TLS':
                            resp = sock_ssl.recv(4096)
                        else:
                            resp = sock.recv(4096)

                        try:
                            headers = parse_message(resp.decode())
                            bye = headers['method']
                            print(
                                self.c.CYAN + '[<=] Response from %s to %s: %s' % (dst, src, bye))
                            if self.verbose == 1 and self.ofile == '':
                                print(self.c.GREEN + resp.decode())

                            if self.ofile != '':
                                fw.write('[<=] Response from %s to %s: %s\n' %
                                         (dst, src, response))
                                if self.verbose == 1:
                                    fw.write(resp.decode() + '\n')
                        except:
                            pass

                    # send 200 Ok
                    cseq = headers['cseq']
                    msg = create_response_ok(src, dst, self.proto, self.domain, lport, int(
                        cseq), branch, callid, tag, totag)

                    print(self.c.YELLOW +
                          '[=>] Sending 200 Ok from %s to %s\n' % (src, dst))

                    if self.verbose == 1 and self.ofile == '':
                        print(self.c.YELLOW + msg)

                    print(self.NORMAL)

                    if self.ofile != '':
                        fw.write('[=>] Sending 200 Ok from %s to %s\n' %
                                 (src, dst))
                        if self.verbose == 1:
                            fw.write(msg + '\n')

                    if self.proto == 'TLS':
                        sock_ssl.sendall(bytes(msg[:8192], 'utf-8'))
                    else:
                        sock.sendto(bytes(msg[:8192], 'utf-8'), host)
            except socket.timeout:
                pass
            except:
                pass
            finally:
                sock.close()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.sdes == 1:
            self.sdp = 2

        if self.nocolor == 1:
            self.c.ansy()

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        if self.rport == 5060 and self.proto == 'TLS':
            self.rport = 5061

        # my IP address
        local_ip = self.localip
        if self.localip == '':
            local_ip = get_machine_default_ip()
            self.localip = local_ip

        self.ip = str(self.ip)

        logo = Logo('sipinvite')
        logo.print()

        if self.auth_user != '' and self.auth_pwd != '' and self.from_user == '100':
            self.from_user = self.auth_user

        # create a list of callers
        origin = []
        for p in self.from_user.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    origin.append(x)
            else:
                origin.append(p)

        # create a list of callees
        destinations = []
        for p in self.to_user.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    destinations.append(x)
            else:
                destinations.append(p)

        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(origin, destinations)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

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
        if self.from_domain != '':
            print(self.c.BWHITE + '[✓] Customized From Domain: ' +
                  self.c.GREEN + '%s' % self.from_domain)
        if self.to_name != '':
            print(self.c.BWHITE + '[✓] Customized To Name: ' +
                  self.c.GREEN + '%s' % self.to_name)
        if self.to_domain != '':
            print(self.c.BWHITE + '[✓] Customized To Domain: ' +
                  self.c.GREEN + '%s' % self.to_domain)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[✓] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)
        print(self.c.BWHITE+'[✓] Total threads: ' +
              self.c.GREEN + '%d' % nthreads)
        print(self.c.BWHITE + '[✓] Call From: ' +
              self.c.YELLOW + '%s' % self.from_user)
        print(self.c.BWHITE + '[✓] Call To: ' +
              self.c.YELLOW + '%s' % self.to_user)
        print(self.c.WHITE)

        # SIP headers
        if self.domain == '':
            self.domain = self.host
        if self.domain == '':
            self.domain = self.ip
        if self.from_domain == '':
            self.from_domain = self.domain
        if self.to_domain == '':
            self.to_domain = self.domain
        if self.contact_domain == '':
            self.contact_domain = local_ip
        if self.nosdp != None and self.nosdp == 1:
            self.sdp = 0

        if self.proxy != '':
            self.route = '<sip:%s;lr>' % self.proxy

        if self.ofile != '':
            fw = open(self.ofile, 'w')

            fw.write('[✓] Target: %s:%s/%s\n' %
                     (self.ip, self.rport, self.proto))
            if self.proxy != '':
                fw.write('[✓] Outbound Proxy: ' + self.c.GREEN + '%s' % self.proxy)
            if self.domain != '' and self.domain != str(self.ip) and self.domain != self.host:
                fw.write('[✓] Customized Domain: %s\n' % self.domain)
            if self.contact_domain != '':
                fw.write('[✓] Customized Contact Domain: %s\n' %
                         self.contact_domain)
            if self.from_name != '':
                fw.write('[✓] Customized From Name: %s\n' % self.from_name)
            if self.from_domain != '':
                fw.write('[✓] Customized From Domain: %s\n' % self.from_domain)
            if self.to_name != '':
                fw.write('[✓] Customized To Name: %s\n' % self.to_name)
            if self.to_domain != '':
                fw.write('[✓] Customized To Domain: %s\n' % self.to_domain)
            if self.user_agent != 'pplsip':
                fw.write('[✓] Customized User-Agent: %s\n' % self.user_agent)
            fw.write('[✓] Total threads: %d' % nthreads)
            fw.write('[✓] Call From: %s\n' % self.from_user)
            fw.write('[✓] Call To: %s\n' % self.to_user)
            fw.write('\n')

        try:
            with ThreadPoolExecutor(max_workers=nthreads) as executor:
                if self.quit == False:
                    for i, src in enumerate(origin):
                        for j, dst in enumerate(destinations):
                            if self.ofile != '':
                                executor.submit(self.invite, fw, src, dst)
                            else:
                                executor.submit(self.invite, '', src, dst)
        except KeyboardInterrupt:
            print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
            self.quit = True

        if self.ofile != '':
            fw.close()

        return
