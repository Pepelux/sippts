#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"


import pyshark
import signal
import os
import platform
import re
import socket
import threading
import time
from lib.functions import parse_message, parse_digest, searchInterface
from lib.color import Color


class SipSniff:
    def __init__(self):
        self.dev = ''
        self.ofile = ''
        self.proto = 'ALL'
        self.verbose = '0'
        self.auth = 'False'

        self.run = True

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False

        self.c = Color()

    def signal_handler(self, sig, frame):
        print(self.c.BYELLOW + 'You pressed Ctrl+C!')
        print(self.c.BWHITE + '\nStopping sniffer ...')
        print(self.c.WHITE)

        self.stop()

    def stop(self):
        self.run = False
        exit()

    def start(self):
        if not self.verbose:
            self.verbose = '0'
        if self.ofile and self.ofile != '':
            if not re.search('.pcap$', self.ofile):
                self.ofile += '.pcap'

        current_user = os.popen('whoami').read()
        current_user = current_user.strip()
        ops = platform.system()

        if ops == 'Linux' and current_user != 'root':
            print(self.c.WHITE + 'You must be ' + self.c.RED +
                  'root' + self.c.WHITE + ' to use this module')
            return

        self.verbose = int(self.verbose)

        signal.signal(signal.SIGINT, self.signal_handler)
        print(self.c.BYELLOW + '\nPress Ctrl+C to stop')
        print(self.c.WHITE)

        # define capture object
        if self.dev == '':
            networkInterface = searchInterface()
        else:
            networkInterface = self.dev

        print(self.c.BWHITE + '[!] Listening on: ' + self.c.GREEN + '%s' % networkInterface)

        if self.proto == 'all':
            print(self.c.BWHITE + '[!] Protocols: ' + self.c.GREEN + 'UDP, TCP, TLS')
        else:
            print(self.c.BWHITE + '[!] Protocol: ' + self.c.GREEN + '%s' %
                  self.proto.upper())

        if self.ofile != '':
            print(
                self.c.BWHITE + '[!] Save captured data in the file: ' + self.c.GREEN + '%s' % self.ofile)
        if self.auth == 'True':
            print(self.c.BWHITE + '[!]' + self.c.GREEN +
                  ' Capture only authentication digest')
        print(self.c.WHITE)

        self.run = True

        threads = list()

        if self.ofile and self.ofile != '':
            t = threading.Thread(target=self.sniff, args=(
                networkInterface, self.ofile), daemon=True)
            threads.append(t)
            t.start()
            time.sleep(0.1)

        t = threading.Thread(target=self.sniff, args=(
            networkInterface, ''), daemon=True)
        threads.append(t)
        t.start()

        t.join()

    def sniff(self, networkInterface, file):
        if file != '':
            capture = pyshark.LiveCapture(
                interface=networkInterface, output_file=file)
        else:
            if self.proto == 'UDP':
                capture = pyshark.LiveCapture(
                    interface=networkInterface, bpf_filter="udp port 5060", include_raw=True, use_json=True)
            elif self.proto == 'TCP':
                capture = pyshark.LiveCapture(
                    interface=networkInterface, bpf_filter="tcp port 5060", include_raw=True, use_json=True)
            elif self.proto == 'TLS':
                capture = pyshark.LiveCapture(
                    interface=networkInterface, bpf_filter="tcp port 5061", include_raw=True, use_json=True)
            else:
                capture = pyshark.LiveCapture(
                    interface=networkInterface, include_raw=True, use_json=True)

        # for packet in capture.sniff_continuously(packet_count=100):
        for packet in capture.sniff_continuously():
            if self.run == False:
                try:
                    capture.clear()
                    capture.close()
                except:
                    pass
                return
            else:
                # adjusted output
                try:
                    if file == '':
                        # get packet content
                        protocol = packet.transport_layer   # protocol type
                        src_addr = packet.ip.src            # source address
                        src_port = packet[protocol].srcport   # source port
                        dst_addr = packet.ip.dst            # destination address
                        # destination port
                        dst_port = packet[protocol].dstport
                        try:
                            mac_addr = packet.eth.src            # MAC address
                        except:
                            mac_addr = ''

                        # TLS connection
                        if self.proto == 'TLS' or self.proto == 'ALL':
                            if src_port == '5061' or dst_port == '5061':
                                if self.auth != 'True' and self.verbose != 0:
                                    print(self.c.YELLOW + 'Found TLS connection %s:%s => %s:%s' %
                                        (src_addr, src_port, dst_addr, dst_port))

                        try:
                            msg = packet[protocol].payload_raw[0]
                            bytes_object = bytes.fromhex(msg)
                            ascii_string = bytes_object.decode("ASCII")
                            headers = parse_message(ascii_string)

                            if headers:
                                ua = headers['ua']
                                method = headers['method']
                                sipuser = headers['sipuser']
                                sipdomain = headers['sipdomain']
                                if sipuser == '':
                                    sipuser = headers['fromuser']

                                # Is a SIP message?
                                if method != '':
                                    if self.auth != 'True' and self.verbose != 0:
                                        print(self.c.WHITE+'[%s] %s:%s => %s:%s - %s' %
                                            (method, src_addr, src_port, dst_addr, dst_port, ua))

                                    ip = socket.gethostbyname(sipdomain)
                                    if ip != sipdomain:
                                        if self.verbose != 0:
                                            print(self.c.BLUE + 'Found Domain %s for user %s connecting to %s:%s' %
                                                (sipdomain, sipuser, dst_addr, dst_port))

                                    try:
                                        auth = headers['auth']
                                        headers_auth = parse_digest(auth)
                                        if headers_auth:
                                            if self.verbose != 0:
                                                print(self.c.GREEN+'Auth=%s\n' % auth)
                                    except:
                                        pass

                                # Search in headers
                                headers = ascii_string.split('\r\n')
                                for header in headers:
                                    m = re.search(
                                        '^Via:\s.*\s([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*', header)
                                    if m:
                                        ipfound = '%s' % (m.group(1))
                                        if self.verbose == 2:
                                            print(self.c.WHITE+'\tFound IP %s in header Via' %
                                                ipfound)

                                    m = re.search(
                                        '^Route:\s\<sip:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*', header)
                                    if m:
                                        ipfound = '%s' % (m.group(1))
                                        if self.verbose == 2:
                                            print(self.c.WHITE+'\tFound IP %s in header Route' %
                                                ipfound)

                                    m = re.search(
                                        '^Record-Route:\s\<sip:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*', header)
                                    if m:
                                        ipfound = '%s' % (m.group(1))
                                        if self.verbose == 2:
                                            print(
                                                self.c.WHITE+'\tFound IP %s in header Record-Route' % ipfound)

                                    m = re.search(
                                        '^From:\s\"*(.*)\"*\s*\<[sip|sips]+:(.*)\@(.*)>.*', header)
                                    if m:
                                        username = '%s' % (m.group(1))
                                        userfound = '%s' % (m.group(2))
                                        ipfound = '%s' % (m.group(3))
                                        if not username:
                                            username = ''
                                        if username == '' and headers_auth['username'] and headers_auth['username'] != '':
                                            username = headers_auth['username']
                                        ipfound = socket.gethostbyname(ipfound)
                                        if self.verbose == 2:
                                            print(self.c.WHITE+'\tFound IP %s in header From' %
                                                ipfound)

                                    m = re.search(
                                        '^To:\s\"*(.*)\"*\s*\<[sip|sips]+:(.*)\@(.*)>.*', header)

                                    if m:
                                        username = '%s' % (m.group(1))
                                        userfound = '%s' % (m.group(2))
                                        ipfound = '%s' % (m.group(3))
                                        if not username:
                                            username = ''
                                        if username == '' and headers_auth['username'] and headers_auth['username'] != '':
                                            username = headers_auth['username']
                                        ipfound = socket.gethostbyname(ipfound)

                                        if self.verbose == 2:
                                            print(self.c.WHITE+'\tFound IP %s in header To' %
                                                ipfound)

                                    m = re.search(
                                        '^Contact:\s\<sip:(.*)\@(.*)>.*>', header)
                                    if m:
                                        userfound = '%s' % (m.group(1))
                                        ipfound = '%s' % (m.group(2))

                                        m = re.search('(.*):([0-9]*)', ipfound)
                                        if m:
                                            ipfound = '%s' % (m.group(1))
                                            portfound = '%s' % (m.group(2))
                                        else:
                                            portfound = '5060'

                                        if self.verbose == 2:
                                            print(self.c.WHITE+'\tFound user %s from IP %s:%s to IP %s:%s in header Contact' %
                                                (userfound, ipfound, portfound, dst_addr, dst_port))

                        except:
                            # Non ASCII data
                            pass
                except pyshark.capture.capture.TSharkCrashException:
                    print("Capture has crashed")
                except AttributeError as e:
                    # ignore packets other than TCP, UDP and IPv4
                    pass
        capture.clear()
        capture.close()
