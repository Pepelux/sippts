#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '4.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
import re
import pyshark
from .lib.functions import parse_digest
from .lib.color import Color
from .lib.logos import Logo

class SipPcapDump:
    def __init__(self):
        self.file = ''
        self.folder = ''
        self.verbose = 0
        self.rtp_extract = 0
        self.sip = 0
        self.rtp = 0

        self.nocolor = ''
        self.c = Color()

    def start(self):
        if self.nocolor == 1:
            self.c.ansy()

        logo = Logo('sippcapdump')
        logo.print()

        if self.folder != '' and not os.path.isdir(self.folder):
            try:
                os.mkdir(self.folder)
            except:
                print(f'Error making folder {self.folder}')
                exit()

        if self.rtp_extract == 1:
            self.extract_rtp()

        if self.sip == 1:
            self.sip_frames()
            self.sip_auth()

        if self.rtp:
            self.rtp_frames()
       
    
    def sip_frames(self):
        capture = pyshark.FileCapture(self.file, display_filter='sip')

        if self.verbose == 1:
            print(self.c.BWHITE + 'SIP frames:' + self.c.WHITE)
            
            if self.folder != '':
                fw = open(f'{self.folder}/sip_frames_full.txt', 'w')

            for packet in capture:
                print(packet)

                if self.folder != '':
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    result = ansi_escape.sub('', str(packet))
                    fw.write(str(result) + '\n')
            
            if self.folder != '':
                fw.close()

            capture.clear()
            capture.close()

        print(self.c.BWHITE + 'SIP dialogs:' + self.c.WHITE)

        if self.folder != '':
            fw = open(f'{self.folder}/sip_frames.txt', 'w')

        capture = pyshark.FileCapture(self.file, display_filter='sip')

        sipcid = []
        sipdata = []
        sipua = []
        
        for packet in capture:
            protocol = packet.transport_layer
            srcip = packet.ip.src
            dstip = packet.ip.dst
            srcport = packet[protocol].srcport
            dstport = packet[protocol].dstport
            cid = packet.sip.call_id
            
            try:
                ua = packet.sip.User_Agent
            except:
                ua = ''

            try:
                sipfrom = f'{packet.sip.From}'
                pos = sipfrom.find(';')
                if pos > 0:
                    sipfrom = sipfrom[0:pos]
            except:
                sipfrom = ''

            try:
                sipto = f'{packet.sip.To}'
                pos = sipto.find(';')
                if pos > 0:
                    sipto = sipto[0:pos]
            except:
                sipto = ''

            try:
                sipcontact = f'{packet.sip.Contact}'
                pos = sipcontact.find('>')
                if pos > 0:
                    sipcontact = sipcontact[0:pos+1]
            except:
                try:
                    sipcontact = f'{packet.sip.Contact_User}@{packet.sip.Contact_Host}'
                except:
                    sipcontact = ''

            try:
                firstline = packet.sip.Request_Line
            except:
                try:
                    firstline = packet.sip.Status_Line
                except:
                    firstline = ''
            
            if ua != '':
                ipua = f'{srcip}###{ua}'
                if ipua not in sipua:
                    sipua.append(ipua)
            
            if cid not in sipcid:
                sipcid.append(cid)
            sipdata.append(f'{cid}###{srcip}###{srcport}###{dstip}###{dstport}###{protocol}###{firstline}')
            
            for cid in sipcid:
                cont = 0
                
                for line in sipdata:
                    if line.find(cid) > -1:
                        cont = cont + 1

                        (c, srcip, srcport, dstip, dstport, protocol, firstline) = line.split('###')

                        data = f'{self.c.BWHITE}{str(cont)}{self.c.WHITE} [{self.c.BYELLOW}{srcip}{self.c.WHITE}:{self.c.BYELLOW}{srcport}{self.c.WHITE} => {self.c.BYELLOW}{dstip}{self.c.WHITE}:{self.c.BYELLOW}{dstport}{self.c.WHITE} {self.c.BWHITE}{protocol}{self.c.WHITE}] {self.c.BGREEN}{firstline}{self.c.WHITE}'
                        dataf = f'{str(cont)} [{srcip}:{srcport} => {dstip}:{dstport} {protocol}] {firstline}'
                        if ua != '':
                            data = f'{data} - UA: {self.c.BMAGENTA}{ua}{self.c.WHITE}'
                            dataf = f'{dataf} - UA: {ua}'
                        if sipfrom != '':
                            data = f'{data} - From: {self.c.BCYAN}{sipfrom}{self.c.WHITE}'
                            dataf = f'{dataf} - From: {sipfrom}'
                        if sipto != '':
                            data = f'{data} - To: {self.c.BCYAN}{sipto}{self.c.WHITE}'
                            dataf = f'{dataf} - To: {sipto}'
                        if sipcontact != '':
                            data = f'{data} - Contact: {self.c.BCYAN}{sipcontact}{self.c.WHITE}'
                            dataf = f'{dataf} - Contact: {sipcontact}'

                        print(data)

                        if self.folder != '':
                            fw.write(dataf + '\n')
                
                print(self.c.WHITE)

                if self.folder != '':
                    fw.write('\n')

        if self.folder != '':
            fw.close()

        print(self.c.BWHITE + 'SIP devices:' + self.c.WHITE)

        if self.folder != '':
            fw = open(f'{self.folder}/sip_devices.txt', 'w')

        for line in sipua:
            (ip, ua) = line.split('###')
            print(f'{self.c.BYELLOW}{ip}{self.c.WHITE} => {self.c.BMAGENTA}{ua}{self.c.WHITE}')

            if self.folder != '':
                fw.write(f'{ip} => {ua}\n')

        if self.folder != '':
            fw.close()

        print(self.c.WHITE)

        capture.clear()
        capture.close()
            
    
    def sip_auth(self):
        print(self.c.BWHITE + 'SIP authentications:' + self.c.WHITE)

        capture = pyshark.FileCapture(self.file, display_filter='sip')

        if self.folder != '':
            fw = open(f'{self.folder}/auth.txt', 'w')

        cont = 0
        sipauth = []
        
        for packet in capture:
            cont = cont + 1
            
            ipsrc = packet.ip.src
            ipdst = packet.ip.dst
            try:
                method = packet.sip.Method
            except:
                method = ''
            try:
                auth = packet.sip.auth
            except:
                auth = ''

            if method != '' and auth != '':
                headers_auth = parse_digest(auth)
                if headers_auth:
                    username = headers_auth['username']
                    realm = headers_auth['realm']
                    uri = headers_auth['uri']
                    nonce = headers_auth['nonce']
                    cnonce = headers_auth['cnonce']
                    nc = headers_auth['nc']
                    qop = headers_auth['qop']
                    algorithm = headers_auth['algorithm']
                    response = headers_auth['response']

                    # File format:
                    # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response
                    authline = '%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s\n' % (
                        ipsrc, ipdst, username, realm, method, uri, nonce, cnonce, nc, qop, algorithm, response)

                    if response not in sipauth:
                        sipauth.append(response)

                        print(f'{self.c.WHITE}[{self.c.BYELLOW}{ipsrc}{self.c.WHITE} => {self.c.BYELLOW}{ipdst}{self.c.WHITE}] User: {self.c.BGREEN}{username}{self.c.WHITE} - Hash: {self.c.BRED}{response}{self.c.WHITE}')

                        if self.folder != '':
                            fw.write(authline + '\n')

        if self.folder != '':
            fw.close()
        
        if cont > 0:
            print(self.c.WHITE)
            print(f'{self.c.BWHITE}To crack hashes use \'{self.c.BGREEN}sippts dump{self.c.BWHITE}\' and \'{self.c.BGREEN}sippts dcrack{self.c.WHITE}\'')
            
        capture.clear()    
        capture.close()
        
        print(self.c.WHITE)
    
    
    def rtp_frames(self):
        print(self.c.BWHITE + 'RTP frames:' + self.c.WHITE)

        capture = pyshark.FileCapture(self.file, display_filter='rtp')

        if self.verbose == 1:
            if self.folder != '':
                fw = open(f'{self.folder}/rtp_frames_full.txt', 'w')

            for packet in capture:
                print(packet)

                if self.folder != '':
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    result = ansi_escape.sub('', str(packet))
                    fw.write(str(result) + '\n')

            if self.folder != '':
                fw.close()
            
            capture.clear()
            capture.close()

        if self.folder != '':
            fw = open(f'{self.folder}/rtp_frames.txt', 'w')

        capture = pyshark.FileCapture(self.file, display_filter='rtp')

        for packet in capture:
            try:
                protocol = packet.transport_layer
            except:
                protocol = ''
            srcip = packet.ip.src
            dstip = packet.ip.dst
            try:
                srcport = packet[protocol].srcport
            except:
                srcport = ''
            try:
                dstport = packet[protocol].dstport
            except:
                dstport = ''
            
            try:
                ua = packet.sip.User_Agent
            except:
                ua = ''

            try:
                sipfrom = f'{packet.sip.From_User}@{packet.sip.From_Host}'
            except:
                sipfrom = ''

            try:
                sipto = f'{packet.sip.To_User}@{packet.sip.To_Host}'
            except:
                sipto = ''

            try:
                sipcontact = f'{packet.sip.Contact_User}@{packet.sip.Contact_Host}'
            except:
                sipcontact = ''

            try:
                firstline = packet.sip.Request_Line
            except:
                try:
                    firstline = packet.sip.Status_Line
                except:
                    firstline = ''
            
            data = f'[{self.c.BYELLOW}{srcip}{self.c.WHITE}:{self.c.BYELLOW}{srcport}{self.c.WHITE} => {self.c.BYELLOW}{dstip}{self.c.WHITE}:{self.c.BYELLOW}{dstport}{self.c.WHITE} {self.c.BWHITE}RTP{self.c.WHITE}] {self.c.BGREEN}{firstline}{self.c.WHITE}'
            dataf = f'[{srcip}:{srcport} => {dstip}:{dstport} {protocol}] {firstline}'
            if ua != '':
                data = f'{data} - UA: {self.c.BMAGENTA}{ua}{self.c.WHITE}'
                dataf = f'{data} - UA: {ua}'
            if sipfrom != '':
                data = f'{data} - From: {self.c.BCYAN}{sipfrom}{self.c.WHITE}'
                dataf = f'{data} - From: {sipfrom}'
            if sipto != '':
                data = f'{data} - To: {self.c.BCYAN}{sipto}{self.c.WHITE}'
                dataf = f'{data} - To: {sipto}'
            if sipcontact != '':
                data = f'{data} - Contact: {self.c.BCYAN}{sipcontact}{self.c.WHITE}'
                dataf = f'{data} - Contact: {sipcontact}'
            
            print(data)

            if self.folder != '':
                fw.write(dataf + '\n')

        if self.folder != '':
            fw.close()
        
        capture.clear()
        capture.close()
        
        print(self.c.WHITE)
    
    
    def extract_rtp(self):
        print(self.c.BYELLOW + 'Looking for RTP conversations ...' + self.c.WHITE)

        if self.which('sox') == None:
            print('Error: sox not found')
            exit()
        
        if self.which('ffmpeg') == None:
            print('Error: ffmpeg not found')
            exit()

        ssrc = []

        pos = self.file.rfind('.')
        self.folder = self.file[0:pos]
        pos = self.folder.rfind('/')
        if pos > -1:
            self.folder = self.folder[pos+1:]

        if not os.path.isdir(self.folder):
            try:
                os.mkdir(self.folder)
            except:
                print(f'Error making folder {self.folder}')
                exit()

        os.system(f'tshark -i - < {self.file} > sippts_dump.txt 2>/dev/null')

        f = open('sippts_dump.txt', 'r')
        for line in f:
            line = line.replace('\n', '')
            m = re.search(r'.*RTP.*SSRC=(0x[a-f|A-F|0-9]*),.*', line)
            if m:
                val = m.group(1)
                if val not in ssrc:
                    ssrc.append(val)
            
        f.close()
        os.remove('sippts_dump.txt')
        cont = 0

        for s in ssrc:
            cont = cont + 1
            name = s[2:]
            os.system(f"tshark -n -r {self.file} -2 -R rtp -R 'rtp.ssrc == {s}' -T fields -e rtp.payload | tr -d '\n',':' | xxd -r -ps >{self.folder}/{name}.rtp")
            os.system(f"sox -t ul -r 8000 -c 1 {self.folder}/{name}.rtp {self.folder}/{name}_sox.wav")
            os.system(f"ffmpeg -f g722 -i {self.folder}/{name}.rtp -acodec pcm_s16le -ar 16000 -ac 1 {self.folder}/{name}_ffmpeg.wav")

            os.remove(f'{self.folder}/{name}.rtp')

        if cont > 0:
            print(self.c.YELLOW + f'Saved {cont} WAV files in {self.folder}')
        else:
            print(self.c.RED + 'No RTP conversations found')
