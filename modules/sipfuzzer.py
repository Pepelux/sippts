#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.3'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import sys
import ssl
import socket
import fcntl
import os
import time
import signal
import threading
import base64
from datetime import datetime
from lib.functions import create_message, get_free_port
from lib.functions_fuzz import create_fuzzed_msg
from lib.color import Color


class SipFuzzer:
    def __init__(self):
        self.ip = ''
        self.proxy = ''
        self.route = ''
        self.port = '5060'
        self.proto = 'UDP'
        self.verbose = '0'
        self.delay = 0
        self.user_agent = 'pplsip'

        self.f = None

        self.quit = False

        self.c = Color()

    def signal_handler(self, sig, frame):
        self.stop()

    def stop(self):
        self.quit = True
        time.sleep(0.1)
        print(self.c.BYELLOW + '\nYou pressed Ctrl+C!')
        print(self.c.BWHITE + '\nStopping fuzzer ... wait a moment\n')
        print(self.c.WHITE)

    def ping(self):
        while self.quit == False:
            if self.verbose == 1:
                print(self.c.YELLOW + '\nPinging server ...' + self.c.WHITE)

            try:
                if self.proto == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(self.c.RED + 'Failed to create socket' + self.c.WHITE)
                self.quit = True
                return

            bind = '0.0.0.0'
            lport = get_free_port()

            try:
                sock.bind((bind, lport))
            except:
                lport = get_free_port()
                sock.bind((bind, lport))

            if self.proxy == '':
                host = (str(self.ip), int(self.port))
            else:
                if self.proxy.find(':') > 0:
                    (proxy_ip, proxy_port) = self.proxy.split(':')
                else:
                    proxy_ip = self.proxy
                    proxy_port = '5060'

                host = (str(proxy_ip), int(proxy_port))

            try:
                if self.proto == 'UDP':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(self.c.RED + 'Failed to create socket' + self.c.WHITE)
                sys.exit(1)

            sock.settimeout(3)

            if self.proto == 'TCP':
                sock.connect(host)

            if self.proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
                sock_ssl.connect(host)

            ping = create_message('OPTIONS', '', self.ip, '100', '', self.ip, '100', '', self.ip,
                                  self.proto, self.ip, self.user_agent, lport, '', '', '', 1, '', '', 1, '', 0, '', self.route, '', '', '', 1)

            try:
                if self.proto == 'TLS':
                    sock_ssl.sendall(bytes(ping[:8192], 'utf-8'))
                    # time.sleep(1)
                    sock_ssl.recv(4096)
                else:
                    sock.sendto(bytes(ping[:8192], 'utf-8'), host)
                    # time.sleep(1)
                    sock.recv(4096)

                self.f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
                self.f.write(' - PING\n')

                if self.verbose == 1:
                    print(self.c.GREEN + 'Ping response Ok' + self.c.WHITE)

                self.f.write(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
                self.f.write(' - PONG\n')
            except socket.timeout:
                # Timeout for ping
                print(
                    self.c.RED + '\nSocket timeout. Server is not responding. Stopping ...')
                print(self.c.RED + 'Check file fuzz.log' + self.c.WHITE)
                self.quit = True
            except:
                # No response for ping
                print(
                    self.c.RED + '\nConnection error. Server is not responding. Stopping ...')
                print(self.c.RED + 'Check file fuzz.log' + self.c.WHITE)
                self.quit = True

            sock.close()
            time.sleep(1+self.delay)

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(self.c.BYELLOW + '\nPress Ctrl+C to stop')
        print(self.c.WHITE)

        print(self.c.BWHITE + '[✓] Target: ' + self.c.GREEN + '%s:%s/%s' %
              (self.ip, self.port, self.proto))
        if self.proxy != '':
            print(self.c.BWHITE + '[✓] Outbound Proxy: ' + self.c.GREEN + '%s' %
                  self.proxy)
        if self.user_agent != 'pplsip':
            print(self.c.BWHITE + '[✓] Customized User-Agent: ' +
                  self.c.GREEN + '%s' % self.user_agent)
        print(self.c.WHITE)

        if self.proxy != '':
            self.route = '<sip:%s;lr>' % self.proxy

        file = 'fuzz.log'
        self.f = open(file, 'w')

        threads = list()

        # Ping
        t = threading.Thread(target=self.ping, daemon=True)
        threads.append(t)
        t.start()

        # Fuzzer
        t = threading.Thread(target=self.fuzz, daemon=True)
        threads.append(t)
        t.start()

        for i, t in enumerate(threads):
            t.join()
            print(self.c.BYELLOW +
                  '[!] Thread %d closed ...' % (i+1) + self.c.WHITE)

        self.f.close()
        sys.exit()

    def fuzz(self):
        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket' + self.c.WHITE)
            return
        fcntl.fcntl(sock, fcntl.F_SETFL, os.O_NONBLOCK)

        bind = '0.0.0.0'
        lport = get_free_port()
        sock.bind((bind, lport))

        if self.proxy == '':
            host = (str(self.ip), int(self.port))
        else:
            if self.proxy.find(':') > 0:
                (proxy_ip, proxy_port) = self.proxy.split(':')
            else:
                proxy_ip = self.proxy
                proxy_port = '5060'

            host = (str(proxy_ip), int(proxy_port))

        sock.settimeout(1)

        c = 1

        if self.proto == 'TCP':
            sock.connect(host)

        if self.proto == 'TLS':
            sock_ssl = ssl.wrap_socket(
                sock, ssl_version=ssl.PROTOCOL_TLS, ciphers=None, cert_reqs=ssl.CERT_NONE)
            sock_ssl.connect(host)

        while self.quit == False:
            try:
                msg = create_fuzzed_msg(all)

                if self.quit == False:
                    print(self.c.BWHITE + '[%d] Sending data to %s:%d/%s ...' %
                          (c, self.ip, self.port, self.proto) + self.c.WHITE, end="\r")
                    c += 1

                    if self.verbose == 1:
                        print(msg)

                    base64_bytes = base64.b64encode(msg)
                    data = base64_bytes.decode('ascii')

                    self.f.write(datetime.utcnow().strftime(
                        "%Y-%m-%d %H:%M:%S"))
                    self.f.write(' - Sending ...\n' + data + '\n')

                    try:
                        if self.proto == 'TLS':
                            sock_ssl.sendall(msg)
                        else:
                            sock.sendto(msg, host)
                    except:
                        pass
            except socket.timeout:
                pass
            except:
                pass

            if self.delay != 0:
                time.sleep(self.delay)

        sock.close()
