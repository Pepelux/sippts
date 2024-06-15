#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '4.0'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
import re
from .lib.color import Color
from .lib.logos import Logo

# https://www.wireshark.org/docs/dfref/s/sip.html


class SipShark:
    def __init__(self):
        self.file = ''
        self.ofile = ''
        self.filter = 'None'

        self.cid = ''
        self.method = ''
        self.frame = ''
        self.rtp_extract = 0

        self.nocolor = ''
        self.c = Color()

    def start(self):
        if self.nocolor == 1:
            self.c.ansy()

        logo = Logo('siptshark')
        logo.print()

        if self.which('tshark') == None:
            print('Error: tshark not found')
            exit()

        if self.filter.lower()[0:6] == 'method':
            (self.filter, self.method) = self.filter.split(' ')
            self.method = self.method.upper()

        if self.filter.lower()[0:5] == 'frame':
            (self.filter, self.frame) = self.filter.split(' ')

        if self.filter.lower() != 'callids' and self.filter.lower()[0:6] == 'callid':
            (self.filter, self.cid) = self.filter.split(' ')

        if self.filter.lower() == 'stats':
            print(self.c.BYELLOW + 'Dialog statistics:' + self.c.WHITE)
            print(self.c.GREEN)
            os.system(
                "tshark -r %s -d udp.port==5060,sip -q -z sip,stat" % self.file)
            print(self.c.WHITE)

        if self.filter.lower() == 'messages':
            print(self.c.BYELLOW + 'SIP messages:' + self.c.WHITE)
            print(self.c.WHITE)
            os.system("tshark -r %s -Y sip" % self.file)
            print(self.c.GREEN)

        if self.filter.lower() == 'frames':
            print(self.c.BYELLOW + 'Frames:' + self.c.WHITE)
            print(self.c.WHITE)
            os.system(
                "tshark -r %s -Y sip -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % self.file)
            print(self.c.WHITE)

        if self.frame != '':
            os.system(
                "tshark -r %s -Y '(frame.number==%s)' -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % (self.file, self.frame))

        if self.method != '':
            os.system(
                "tshark -r %s -Y 'sip.CSeq.method eq %s'" % (self.file, self.method))

        if self.filter.lower() == 'callids':
            print(self.c.BYELLOW + 'Captured CallerID from dialogs:' + self.c.WHITE)
            print(self.c.WHITE)
            os.system(
                "tshark -r %s -T fields -e sip.Call-ID |sort |uniq" % self.file)
            print(self.c.WHITE)

        if self.cid != '':
            os.system(
                "tshark -r %s -Y 'sip.Call-ID eq \"%s\"' -T fields -e sip.msg_hdr |sed 's/\\\\r\\\\n/\\n/g'" % (self.file, self.cid))

        if self.filter.lower() == 'rtp':
            print(self.c.BYELLOW + 'Captured RTP streams:' + self.c.WHITE)
            print(self.c.CYAN)
            os.system("tshark -r %s -q -z rtp,streams" % self.file)
            print(self.c.WHITE)

        if self.filter.lower() == 'auth':
            print(self.c.BYELLOW + 'Captured Authentication Digest:' + self.c.WHITE)
            print(self.c.GREEN)
            os.system(
                "tshark -r %s -Y sip -T fields -e sip.auth |grep username |sort |uniq |sed 's/\\\\r\\\\n/\\n/g'" % self.file)
            print(self.c.WHITE)

        if self.rtp_extract == 1:
            self.extract_rtp()
       
    
    # Check if apps are installed
    def which(self, program):
        import os
        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in os.environ.get("PATH", "").split(os.pathsep):
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file

        return None
    
    
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

        os.system(f'tshark -i - < {self.file} > sippts_tshark.txt 2>/dev/null')

        f = open('sippts_tshark.txt', 'r')
        for line in f:
            line = line.replace('\n', '')
            m = re.search(r'.*RTP.*SSRC=(0x[a-f|A-F|0-9]*),.*', line)
            if m:
                val = m.group(1)
                if val not in ssrc:
                    ssrc.append(val)
            
        f.close()
        os.remove('sippts_tshark.txt')

        for s in ssrc:
            name = s[2:]
            os.system(f"tshark -n -r {self.file} -2 -R rtp -R 'rtp.ssrc == {s}' -T fields -e rtp.payload | tr -d '\n',':' | xxd -r -ps >{self.folder}/{name}.rtp")
            os.system(f"sox -t ul -r 8000 -c 1 {self.folder}/{name}.rtp {self.folder}/{name}_sox.wav")
            os.system(f"ffmpeg -f g722 -i {self.folder}/{name}.rtp -acodec pcm_s16le -ar 16000 -ac 1 {self.folder}/{name}_ffmpeg.wav")

            os.remove(f'{self.folder}/{name}.rtp')
