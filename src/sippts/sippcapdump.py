#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import os
import sys
import re
import shutil
import subprocess
import pyshark
from .lib.functions import parse_digest, packet_addresses, pyshark_compat, close_capture
from .lib.color import Color
from .lib.logos import Logo


class SipPcapDump:
    def __init__(self):
        self.file = ""
        self.folder = ""
        self.verbose = 0
        self.rtp_extract = 0
        self.sip = 0
        self.rtp = 0
        self.auth = 0

        self.nocolor = 0
        self.c = Color()

    def start(self):
        pyshark_compat()

        try:
            self.nocolor = int(self.nocolor)
        except:
            self.nocolor = 0

        if self.nocolor == 1:
            self.c.ansy()

        logo = Logo("sippcapdump", self.nocolor)
        logo.print()

        if self.folder != "" and not os.path.isdir(self.folder):
            try:
                os.mkdir(self.folder)
            except:
                print(f"Error making folder {self.folder}")
                sys.exit()

        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        try:
            self.rtp_extract = int(self.rtp_extract)
        except:
            self.rtp_extract = 0

        try:
            self.sip = int(self.sip)
        except:
            self.sip = 0

        try:
            self.rtp = int(self.rtp)
        except:
            self.rtp = 0

        try:
            self.auth = int(self.auth)
        except:
            self.auth = 0

        if self.rtp_extract == 1:
            self.extract_rtp()

        if self.sip:
            self.sip_frames()
            self.sip_auth()

        if self.rtp:
            self.rtp_frames()

        if self.auth and not self.sip:
            self.sip_auth()

    def sip_frames(self):
        capture = pyshark.FileCapture(self.file, display_filter="sip")

        if self.verbose == 1:
            print(f"{self.c.BWHITE}SIP frames:{self.c.WHITE}")

            if self.folder != "":
                fw = open(f"{self.folder}/sip_frames_full.txt", "w")

            for packet in capture:
                print(packet)

                if self.folder != "":
                    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                    result = ansi_escape.sub("", str(packet))
                    fw.write(str(result) + "\n")

            if self.folder != "":
                fw.close()

            close_capture(capture)

        print(f"{self.c.BWHITE}SIP dialogs:{self.c.WHITE}")

        if self.folder != "":
            fw = open(f"{self.folder}/sip_frames.txt", "w")

        capture = pyshark.FileCapture(self.file, display_filter="sip")

        sipcid = []
        sipdata = []
        sipdevices = []

        for packet in capture:
            protocol = packet.transport_layer
            (srcip, dstip) = packet_addresses(packet)

            if srcip == None:
                continue

            srcport = packet[protocol].srcport
            dstport = packet[protocol].dstport

            try:
                cid = packet.sip.call_id
            except:
                cid = ""

            try:
                ua = packet.sip.User_Agent
            except:
                ua = ""

            try:
                sipfrom = f"{packet.sip.From}"
                pos = sipfrom.find(";")
                if pos > 0:
                    sipfrom = sipfrom[0:pos]
            except:
                sipfrom = ""

            try:
                sipto = f"{packet.sip.To}"
                pos = sipto.find(";")
                if pos > 0:
                    sipto = sipto[0:pos]
            except:
                sipto = ""

            try:
                sipcontact = f"{packet.sip.Contact}"
                pos = sipcontact.find(">")
                if pos > 0:
                    sipcontact = sipcontact[0 : pos + 1]
            except:
                try:
                    sipcontact = f"{packet.sip.Contact_User}@{packet.sip.Contact_Host}"
                except:
                    sipcontact = ""

            try:
                firstline = packet.sip.Request_Line
            except:
                try:
                    firstline = packet.sip.Status_Line
                except:
                    firstline = ""

            ipua = f"{srcip}###{ua}"
            if ipua not in sipdevices:
                sipdevices.append(ipua)

            if cid not in sipcid:
                sipcid.append(cid)

            # every field of the packet travels with it: the dialogs are printed
            # after reading the whole capture, not once per packet
            sipdata.append(
                f"{cid}###{srcip}###{srcport}###{dstip}###{dstport}###{protocol}###{firstline}###{ua}###{sipfrom}###{sipto}###{sipcontact}"
            )

        for cid in sipcid:
            cont = 0

            for line in sipdata:
                (
                    c,
                    srcip,
                    srcport,
                    dstip,
                    dstport,
                    protocol,
                    firstline,
                    ua,
                    sipfrom,
                    sipto,
                    sipcontact,
                ) = line.split("###")

                if c != cid:
                    continue

                cont = cont + 1

                data = f"{self.c.BWHITE}{str(cont)}{self.c.WHITE} [{self.c.BYELLOW}{srcip}{self.c.WHITE}:{self.c.BYELLOW}{srcport}{self.c.WHITE} => {self.c.BYELLOW}{dstip}{self.c.WHITE}:{self.c.BYELLOW}{dstport}{self.c.WHITE} {self.c.BWHITE}{protocol}{self.c.WHITE}] {self.c.BGREEN}{firstline}{self.c.WHITE}"
                dataf = f"{str(cont)} [{srcip}:{srcport} => {dstip}:{dstport} {protocol}] {firstline}"
                if ua != "":
                    data = f"{data} - UA: {self.c.BMAGENTA}{ua}{self.c.WHITE}"
                    dataf = f"{dataf} - UA: {ua}"
                if sipfrom != "":
                    data = f"{data} - From: {self.c.BCYAN}{sipfrom}{self.c.WHITE}"
                    dataf = f"{dataf} - From: {sipfrom}"
                if sipto != "":
                    data = f"{data} - To: {self.c.BCYAN}{sipto}{self.c.WHITE}"
                    dataf = f"{dataf} - To: {sipto}"
                if sipcontact != "":
                    data = f"{data} - Contact: {self.c.BCYAN}{sipcontact}{self.c.WHITE}"
                    dataf = f"{dataf} - Contact: {sipcontact}"

                print(data)

                if self.folder != "":
                    fw.write(dataf + "\n")

            print(self.c.WHITE)

            if self.folder != "":
                fw.write("\n")

        if self.folder != "":
            fw.close()

        print(f"{self.c.BWHITE}SIP devices:{self.c.WHITE}")

        if self.folder != "":
            fw = open(f"{self.folder}/sip_devices.txt", "w")

        ips = []

        for line in sipdevices:
            (ip, ua) = line.split("###")

            if ip not in ips:
                print(
                    f"{self.c.BYELLOW}{ip}{self.c.WHITE} => {self.c.BMAGENTA}{ua}{self.c.WHITE}"
                )
                if ua != "":
                    ips.append(ip)

            if self.folder != "":
                fw.write(f"{ip} => {ua}\n")

        if self.folder != "":
            fw.close()

        print(self.c.WHITE)

        close_capture(capture)

    def sip_auth(self):
        print(f"{self.c.BWHITE}SIP authentications:{self.c.WHITE}")

        capture = pyshark.FileCapture(self.file, display_filter="sip")

        if self.folder != "":
            fw = open(f"{self.folder}/auth.txt", "w")

        cont = 0
        sipauth = []

        for packet in capture:
            cont = cont + 1

            (ipsrc, ipdst) = packet_addresses(packet)

            if ipsrc == None:
                continue

            try:
                method = packet.sip.Method
            except:
                method = ""
            try:
                auth = packet.sip.auth
            except:
                auth = ""

            if method != "" and auth != "":
                headers_auth = parse_digest(auth)
                if headers_auth:
                    username = headers_auth["username"]
                    realm = headers_auth["realm"]
                    uri = headers_auth["uri"]
                    nonce = headers_auth["nonce"]
                    cnonce = headers_auth["cnonce"]
                    nc = headers_auth["nc"]
                    qop = headers_auth["qop"]
                    algorithm = headers_auth["algorithm"]
                    response = headers_auth["response"]

                    # File format:
                    # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response
                    authline = '%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s"%s\n' % (
                        ipsrc,
                        ipdst,
                        username,
                        realm,
                        method,
                        uri,
                        nonce,
                        cnonce,
                        nc,
                        qop,
                        algorithm,
                        response,
                    )

                    if f"{username}#{uri}" not in sipauth:
                        sipauth.append(f"{username}#{uri}")

                        print(
                            f"{self.c.WHITE}[{self.c.BYELLOW}{ipsrc}{self.c.WHITE} => {self.c.BYELLOW}{ipdst}{self.c.WHITE}] User: {self.c.BGREEN}{username}{self.c.WHITE} - URI: {self.c.BCYAN}{uri}{self.c.WHITE} - Hash: {self.c.BRED}{response}{self.c.WHITE}"
                        )

                        if self.folder != "":
                            fw.write(authline + "\n")

        if self.folder != "":
            fw.close()

        if cont > 0:
            print(self.c.WHITE)
            print(
                f"{self.c.BWHITE}To crack hashes use '{self.c.BGREEN}sippts dump{self.c.BWHITE}' and '{self.c.BGREEN}sippts dcrack{self.c.WHITE}'"
            )

        close_capture(capture)

        print(self.c.WHITE)

    def rtp_frames(self):
        print(f"{self.c.BWHITE}RTP frames:{self.c.WHITE}")

        capture = pyshark.FileCapture(self.file, display_filter="rtp")

        if self.verbose == 1:
            if self.folder != "":
                fw = open(f"{self.folder}/rtp_frames_full.txt", "w")

            for packet in capture:
                print(packet)

                if self.folder != "":
                    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                    result = ansi_escape.sub("", str(packet))
                    fw.write(str(result) + "\n")

            if self.folder != "":
                fw.close()

            close_capture(capture)

        if self.folder != "":
            fw = open(f"{self.folder}/rtp_frames.txt", "w")

        capture = pyshark.FileCapture(self.file, display_filter="rtp")

        for packet in capture:
            try:
                protocol = packet.transport_layer
            except:
                protocol = ""
            (srcip, dstip) = packet_addresses(packet)

            if srcip == None:
                continue

            try:
                srcport = packet[protocol].srcport
            except:
                srcport = ""
            try:
                dstport = packet[protocol].dstport
            except:
                dstport = ""

            try:
                ua = packet.sip.User_Agent
            except:
                ua = ""

            try:
                sipfrom = f"{packet.sip.From_User}@{packet.sip.From_Host}"
            except:
                sipfrom = ""

            try:
                sipto = f"{packet.sip.To_User}@{packet.sip.To_Host}"
            except:
                sipto = ""

            try:
                sipcontact = f"{packet.sip.Contact_User}@{packet.sip.Contact_Host}"
            except:
                sipcontact = ""

            try:
                firstline = packet.sip.Request_Line
            except:
                try:
                    firstline = packet.sip.Status_Line
                except:
                    firstline = ""

            data = f"[{self.c.BYELLOW}{srcip}{self.c.WHITE}:{self.c.BYELLOW}{srcport}{self.c.WHITE} => {self.c.BYELLOW}{dstip}{self.c.WHITE}:{self.c.BYELLOW}{dstport}{self.c.WHITE} {self.c.BWHITE}RTP{self.c.WHITE}] {self.c.BGREEN}{firstline}{self.c.WHITE}"
            dataf = f"[{srcip}:{srcport} => {dstip}:{dstport} {protocol}] {firstline}"
            if ua != "":
                data = f"{data} - UA: {self.c.BMAGENTA}{ua}{self.c.WHITE}"
                dataf = f"{dataf} - UA: {ua}"
            if sipfrom != "":
                data = f"{data} - From: {self.c.BCYAN}{sipfrom}{self.c.WHITE}"
                dataf = f"{dataf} - From: {sipfrom}"
            if sipto != "":
                data = f"{data} - To: {self.c.BCYAN}{sipto}{self.c.WHITE}"
                dataf = f"{dataf} - To: {sipto}"
            if sipcontact != "":
                data = f"{data} - Contact: {self.c.BCYAN}{sipcontact}{self.c.WHITE}"
                dataf = f"{dataf} - Contact: {sipcontact}"

            print(data)

            if self.folder != "":
                fw.write(dataf + "\n")

        if self.folder != "":
            fw.close()

        close_capture(capture)

        print(self.c.WHITE)

    def which(self, program):
        """
        Path of an external tool, or None when it is not installed.

        It was called without being defined anywhere, so -r died with
        AttributeError before looking at the capture. tshark is asked to
        pyshark first, which knows where it lives outside the PATH (inside
        the Wireshark bundle on macOS, for instance).
        """
        if program == "tshark":
            try:
                from pyshark.tshark.tshark import get_process_path

                return get_process_path()
            except Exception:
                pass

        return shutil.which(program)

    def extract_rtp(self):
        print(f"{self.c.BYELLOW}Looking for RTP conversations ...{self.c.WHITE}")

        if self.which("sox") == None:
            print(f"{self.c.RED}Error: sox not found")
            print(self.c.WHITE)
            sys.exit()

        if self.which("ffmpeg") == None:
            print(f"{self.c.RED}Error: ffmpeg not found")
            print(self.c.WHITE)
            sys.exit()

        if self.which("tshark") == None:
            print(f"{self.c.RED}Error: tshark not found")
            print(self.c.WHITE)
            sys.exit()

        if self.which("xxd") == None:
            print(f"{self.c.RED}Error: xxd not found")
            print(self.c.WHITE)
            sys.exit()

        tshark_bin = self.which("tshark")

        ssrc = []

        # the folder given with -folder is respected: only when there is none
        # the name of the capture is used
        if self.folder == "":
            pos = self.file.rfind(".")
            self.folder = self.file[0:pos]
            pos = self.folder.rfind("/")
            if pos > -1:
                self.folder = self.folder[pos + 1 :]

        if not os.path.isdir(self.folder):
            try:
                os.mkdir(self.folder)
            except:
                print(f"{self.c.RED}Error making folder {self.folder}")
                print(self.c.WHITE)
                sys.exit()

        # the dump goes to a temporary file, not to the current directory,
        # where it collided between runs and needed write permission
        import tempfile

        fd, dumpfile = tempfile.mkstemp(prefix="sippts_dump_", suffix=".txt")
        os.close(fd)

        try:
            with open(dumpfile, "w") as out, open(self.file, "rb") as inp:
                subprocess.run(
                    [tshark_bin, "-i", "-"],
                    stdin=inp,
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                )

            with open(dumpfile, "r") as f:
                for line in f:
                    line = line.replace("\n", "")
                    m = re.search(r".*RTP.*SSRC=(0x[a-f|A-F|0-9]*),.*", line)
                    if m:
                        val = m.group(1)
                        if val not in ssrc:
                            ssrc.append(val)
        finally:
            if os.path.isfile(dumpfile):
                os.remove(dumpfile)

        cont = 0

        for s in ssrc:
            cont = cont + 1
            name = s[2:]

            tshark = subprocess.run(
                [
                    tshark_bin, "-n", "-r", self.file, "-2",
                    "-R", "rtp", "-R", f"rtp.ssrc == {s}",
                    "-T", "fields", "-e", "rtp.payload",
                ],
                stdout=subprocess.PIPE,
            )
            # equivalent to: tr -d '\n,:'
            payload = (
                tshark.stdout.replace(b"\n", b"").replace(b",", b"").replace(b":", b"")
            )
            with open(f"{self.folder}/{name}.rtp", "wb") as out:
                subprocess.run(["xxd", "-r", "-ps"], input=payload, stdout=out)

            subprocess.run(
                [
                    "sox", "-t", "ul", "-r", "8000", "-c", "1",
                    f"{self.folder}/{name}.rtp",
                    f"{self.folder}/{name}_sox.wav",
                ]
            )
            subprocess.run(
                [
                    "ffmpeg", "-f", "g722", "-i", f"{self.folder}/{name}.rtp",
                    "-acodec", "pcm_s16le", "-ar", "16000", "-ac", "1",
                    f"{self.folder}/{name}_ffmpeg.wav",
                ]
            )

            os.remove(f"{self.folder}/{name}.rtp")

        if cont > 0:
            print(f"{self.c.YELLOW}Saved {cont} WAV files in {self.folder}")
        else:
            print(f"{self.c.RED}No RTP conversations found")
