#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jose Luis Verdeguer"
__version__ = "4.1"
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2024, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from threading import Lock
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
import threading
import io
import base64
import os
import time

try:
    import cursor
except:
    pass

from .lib.functions import calculateHash, format_time, open_log
import itertools
import string
from .lib.color import Color
from .lib.logos import Logo


class SipDigestCrack:
    def __init__(self):
        self.file = ""
        self.wordlist = ""
        self.ofile = ""
        self.username = ""
        self.bruteforce = 0
        self.charset = "printable"
        self.min = "1"
        self.max = "8"
        self.prefix = ""
        self.suffix = ""
        self.verbose = 0
        self.threads = 10

        self.pwdvalue = dict()
        self.run = True

        self.totaltime = 0
        self.found = []
        self.saved = []
        self.checked = []
        
        self.lock = None

        self.backupfile = "sipdigestcrack.res"

        self.c = Color()

        self.run_event = threading.Event()
        self.run_event.set()
        signal.signal(signal.SIGINT, self.signal_handler)

    def start(self):
        # reset the stop flag: after a Ctrl+C the object kept it set, so from
        # sippts-gui (where the module instance is reused) every later run
        # did nothing at all
        self.run = True
        self.run_event.set()

        self.lock = Lock()
        
        try:
            self.verbose = int(self.verbose)
        except:
            self.verbose = 0

        if not os.path.isfile(self.file):
            print(f"{self.c.RED}[-] File {self.file} not found")
            print(self.c.WHITE)
            sys.exit()

        if self.charset == "digits":
            self.chars = string.digits
        elif self.charset == "ascii_letters":
            self.chars = string.ascii_letters
        elif self.charset == "ascii_lowercase":
            self.chars = string.ascii_lowercase
        elif self.charset == "ascii_uppercase":
            self.chars = string.ascii_uppercase
        elif self.charset == "hexdigits":
            self.chars = string.hexdigits
        elif self.charset == "octdigits":
            self.chars = string.octdigits
        elif self.charset == "punctuation":
            self.chars = string.punctuation
        elif self.charset == "printable":
            self.chars = string.printable
        elif self.charset == "whitespace":
            self.chars = string.whitespace
        else:
            self.chars = self.charset

        try:
            self.bruteforce = int(self.bruteforce)
        except:
            self.bruteforce = 0

        logo = Logo("sipdigestcrack")
        logo.print()

        print(f"{self.c.BWHITE}[✓] Input file: {self.c.GREEN}{self.file}")
        print(f"{self.c.BWHITE}[✓] Wordlist: {self.c.GREEN}{self.wordlist}")
        print(f"{self.c.BWHITE}[✓] Used threads: {self.c.GREEN}{str(self.threads)}")
        print(self.c.WHITE)

        # the wordlist was opened inside the worker threads, so a wrong path
        # was swallowed by the executor and the run ended with 'Nothing found'
        # as if every password had been tried
        if self.bruteforce == 0:
            try:
                open(self.wordlist, "rb").close()
            except OSError as error:
                print(f"{self.c.RED}Error reading wordlist {self.wordlist} ({error})")
                print(self.c.WHITE)
                return

        print(f"{self.c.BYELLOW}\nPress Ctrl+C to stop")
        print(self.c.WHITE)

        # File format:
        # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response
        try:
            with open(self.file, "r") as f:
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    for line in f:
                        if not self.run_event.is_set():
                            break
                        line = line.strip()
                        values = line.split('"')

                        if len(values) < 12:
                            if line != "":
                                print(
                                    f"{self.c.YELLOW}[!] Skipping line: {line}{self.c.WHITE}"
                                )
                            continue

                        ipsrc = values[0]
                        ipdst = values[1]
                        username = values[2]
                        realm = values[3]
                        method = values[4]
                        uri = values[5]
                        nonce = values[6]
                        cnonce = values[7]
                        nc = values[8]
                        qop = values[9]
                        algorithm = values[10]
                        response = values[11]

                        executor.submit(
                            self.read_data,
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
                    executor.shutdown(wait=True)

            f.close()
        except Exception as e:
            print(f"Exception: {e}")

        self.found.sort()
        self.print()
        
        self.save_file()

    def signal_handler(self, sig, frame):
        self.stop()

    def stop(self):
        print(f"{self.c.BYELLOW}You pressed Ctrl+C!{self.c.WHITE}")
        print(f"{self.c.BWHITE}\nStopping sipcrack ...\n{self.c.WHITE}")
        self.run_event.clear()
        self.run = False

    def read_data(
        self,
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
    ):
        try:
            start = time.time()

            row = "%s#%s#%s#%s" % (ipsrc, ipdst, username, realm)

            # shared between threads: the same user with another nonce has the
            # same password, so it is cracked only once
            with self.lock:
                already = row in self.checked
                if not already:
                    self.checked.append(row)

            if already:
                print(
                    f"{self.c.YELLOW}username {username}@{ipdst} already checked{self.c.WHITE}"
                )
            else:
                print(
                    f"{self.c.BYELLOW}[+] Trying to crack hash {response} of the user {username} ...{self.c.WHITE}".ljust(100)
                )

                found = "false"
                word_start = ""
                try:
                    with io.open(
                        self.backupfile,
                        "r",
                        newline=None,
                        encoding="latin-1",
                    ) as fd:
                        word_start = ""
                        found = "false"

                        for pline in fd:
                            try:
                                pl = pline.replace("\n", "")
                                # type (bf|wl) - chars - prefix - suffix - username - b64(starting_password) - found
                                values = pl.split(":")

                                if values[4] == username:
                                    try:
                                        found = values[6]
                                    except:
                                        found = "false"

                                    if found == "true":
                                        b64pwd = base64.b64decode(values[5]).decode()
                                        word_start = b64pwd

                                        print(
                                            f"{self.c.GREEN}[-] Cleartext password for user {username} is {word_start}{self.c.WHITE}"
                                        )
                                        self.found.append(
                                            "%s###%s###%s###%s"
                                            % (
                                                ipsrc,
                                                ipdst,
                                                username,
                                                word_start,
                                            )
                                        )
                                    else:
                                        if found == "ignore":
                                            print(
                                                f"{self.c.MAGENTA}[-] Ignoring user {username}{self.c.WHITE}"
                                            )
                                        else:
                                            if (
                                                (
                                                    self.bruteforce == 0
                                                    and values[0] == "wl"
                                                    and values[1] == self.wordlist
                                                    and self.prefix == values[2]
                                                    and self.suffix == values[3]
                                                )
                                                or (
                                                    self.bruteforce == 1
                                                    and values[0] == "bf"
                                                    and values[1] == self.chars
                                                    and self.prefix == values[2]
                                                    and self.suffix == values[3]
                                                )
                                            ) and values[4] == username:
                                                b64pwd = base64.b64decode(
                                                    values[5]
                                                ).decode()
                                                word_start = b64pwd

                                                l = len(self.prefix)
                                                word_start = word_start[l:]
                                                l = len(self.suffix)
                                                word_start = word_start[
                                                    0 : len(word_start) - l
                                                ]
                            except:
                                pass

                    fd.close()
                except:
                    pass

                if found == "false":
                    try:
                        cursor.hide()
                    except: 
                        pass
                    pwd = self.crack(
                        response,
                        username,
                        realm,
                        method,
                        uri,
                        nonce,
                        algorithm,
                        cnonce,
                        nc,
                        qop,
                        word_start,
                    )
                    try:
                        cursor.show()
                    except: 
                        pass

                    if pwd != "":
                        print(
                            f"{self.c.GREEN}[-] Cleartext password for user {username} is {pwd}{self.c.WHITE}"
                        )
                        self.found.append(
                            "%s###%s###%s###%s" % (ipsrc, ipdst, username, pwd)
                        )
                    else:
                        if self.run == False:
                            lastpwd = self.pwdvalue.get(username, "")

                            if self.bruteforce == 1:
                                self.save_data(
                                    self.charset, username, lastpwd, "false"
                                )
                            else:
                                self.save_data(
                                    self.wordlist, username, lastpwd, "false"
                                )
                        print(
                            f"{self.c.RED}[-] Password not found. Try with another wordlist{self.c.WHITE}"
                        )

            end = time.time()
            self.totaltime = int(end - start)
        except KeyboardInterrupt:
            self.stop()

    def check_value(self, password, chars):
        pos = len(chars)
        value = 0
        for i, c in enumerate(reversed(password)):
            if c not in chars:
                # the saved password does not belong to this charset, so there
                # is no valid offset: start this length from the beginning
                return 0
            value += (pos**i) * chars.index(c)
        return value

    def save_data(self, wl, usr, pwd, status):
        found = 0

        b64pwd = base64.b64encode(bytes(pwd, "utf-8")).decode()

        if pwd == '' or b64pwd == '':
            return

        try:
            with io.open(
                self.backupfile, "r", newline=None, encoding="latin-1"
            ) as fd:
                for pline in fd:
                    try:
                        pl = pline.replace("\n", "")
                        values = pl.split(":")
                        if (
                            self.bruteforce == 0
                            and values[0] == "wl"
                            and values[1] == wl
                            and values[2] == self.prefix
                            and values[3] == self.suffix
                            and values[4] == usr
                        ):
                            pl = "wl:%s:%s:%s:%s:%s:%s" % (
                                wl,
                                self.prefix,
                                self.suffix,
                                usr,
                                b64pwd,
                                status,
                            )
                            found = 1
                        if (
                            self.bruteforce == 1
                            and values[0] == "bf"
                            and values[1] == self.charset
                            and values[2] == self.prefix
                            and values[3] == self.suffix
                            and values[4] == usr
                        ):
                            pl = "bf:%s:%s:%s:%s:%s:%s" % (
                                self.charset,
                                self.prefix,
                                self.suffix,
                                usr,
                                b64pwd,
                                status,
                            )
                            found = 1
                        if pl not in self.saved:
                            self.saved.append(pl)
                    except:
                        fd.close()
                        return ""

            fd.close()
        except:
            if self.bruteforce == 0:
                pl = "wl:%s:%s:%s:%s:%s:%s" % (
                    wl,
                    self.prefix,
                    self.suffix,
                    usr,
                    b64pwd,
                    status,
                )
            else:
                pl = "bf:%s:%s:%s:%s:%s:%s" % (
                    self.charset,
                    self.prefix,
                    self.suffix,
                    usr,
                    b64pwd,
                    status,
                )
            found = 1
            if pl not in self.saved:
                self.saved.append(pl)

        if found == 0:
            if self.bruteforce == 0:
                pl = "wl:%s:%s:%s:%s:%s:%s" % (
                    wl,
                    self.prefix,
                    self.suffix,
                    usr,
                    b64pwd,
                    status,
                )
            else:
                pl = "bf:%s:%s:%s:%s:%s:%s" % (
                    self.charset,
                    self.prefix,
                    self.suffix,
                    usr,
                    b64pwd,
                    status,
                )
            if pl not in self.saved:
                self.saved.append(pl)

    def save_file(self):
        self.saved.sort()
        aux = []
        aux2 = []
        
        for line in reversed(self.saved):
            values = line.split(":")
            
            tmp = f"{values[0]}:{values[1]}:{values[2]}:{values[3]}:{values[4]}:"            
            if tmp not in aux:
                aux2.append(line)
                
            aux.append(tmp)

        aux2.sort()

        f = open_log(self.backupfile, 'w+')
        
        for line in aux2:
            f.write(line + "\n")
                
        f.close()    

    def crack(
        self,
        response,
        username,
        realm,
        method,
        uri,
        nonce,
        algorithm,
        cnonce,
        nc,
        qop,
        word_start,
    ):
        if self.bruteforce == 1:
            if not self.run_event.is_set():
                return ""

            try:
                START_VALUE = self.check_value(word_start, self.chars)
                # the offset only belongs to the length of the saved password:
                # shorter lengths are already done, longer ones start at 0
                start_len = len(word_start)

                for n in range(int(self.min), int(self.max) + 1):
                    if not self.run_event.is_set():
                        break

                    if n < start_len:
                        continue

                    offset = START_VALUE if n == start_len else 0

                    xs = itertools.product(self.chars, repeat=n)
                    combos = itertools.islice(xs, offset, None)

                    for i, pwd in enumerate(combos, start=offset):
                        if not self.run_event.is_set():
                            break

                        pwd = "".join(pwd)
                        pwd = "%s%s%s" % (self.prefix, pwd, self.suffix)
                        pwd = pwd.replace("\n", "")

                        print(
                            f"{self.c.BWHITE}   [-] Trying pass {self.c.YELLOW}{pwd}{self.c.WHITE} for user {self.c.GREEN}{username}{self.c.WHITE}".ljust(100),
                            end="\r",
                        )

                        self.pwdvalue[username] = pwd

                        if self.verbose == 1:
                            print(f"{self.c.WHITE}\nPassword:{pwd}")
                            print(f"{self.c.WHITE}Expected hash: {response}")
                        if response == calculateHash(
                            username,
                            realm,
                            pwd,
                            method,
                            uri,
                            nonce,
                            algorithm,
                            cnonce,
                            nc,
                            qop,
                            self.verbose,
                            "",
                        ):
                            self.save_data(self.charset, username, pwd, "true")
                            return pwd
            except KeyboardInterrupt:
                self.save_data(self.charset, username, pwd, "false")
                self.stop()
                return ""
            except:
                pass
        else:
            pwd = ""

            with open(self.wordlist, "rb") as fd:
                for pwd in fd:
                    # if not self.run_event.is_set():
                    #     # fd.close()
                    #     self.save_data(self.wordlist, username, pwd, "false")
                    #     self.stop()
                    #     break

                    try:
                        # the candidate is used as it is in the wordlist: any
                        # character removed here is a password that can never
                        # be cracked
                        try:
                            pwd = pwd.decode("utf-8")
                        except UnicodeDecodeError:
                            pwd = pwd.decode("latin-1")

                        pwd = pwd.rstrip("\r\n")

                        print(
                            f"{self.c.BWHITE}   [-] Trying pass {self.c.YELLOW}{pwd}{self.c.WHITE} for user {self.c.GREEN}{username}{self.c.WHITE}".ljust(250),
                            end="\r",
                        )

                        if not self.run_event.is_set():
                            fd.close()
                            self.save_data(self.wordlist, username, pwd, "false")
                            self.stop()
                            break

                        if self.verbose == 1:
                            print(f"{self.c.WHITE}Password: {pwd.ljust(50)}")
                            print(f"{self.c.WHITE}Expected hash: {response}")
                        if response == calculateHash(
                            username,
                            realm,
                            pwd,
                            method,
                            uri,
                            nonce,
                            algorithm,
                            cnonce,
                            nc,
                            qop,
                            self.verbose,
                            "",
                        ):
                            fd.close()
                            self.save_data(self.wordlist, username, pwd, "true")
                            return pwd
                    except KeyboardInterrupt:
                        fd.close()
                        self.save_data(self.wordlist, username, pwd, "false")
                        self.stop()
                        return ""
                    except:
                        pwd = ""
                        pass

            self.save_data(self.wordlist, username, pwd, "false")
            fd.close()
            return ""

        return ""

    def print(self):
        slen = len("Source IP")
        dlen = len("Destination IP")
        ulen = len("Username")
        plen = len("Password")

        for x in self.found:
            (s, d, u, p) = x.split("###")
            if len(s) > slen:
                slen = len(s)
            if len(d) > dlen:
                dlen = len(d)
            if len(u) > ulen:
                ulen = len(u)
            if len(p) > plen:
                plen = len(p)

        tlen = slen + dlen + ulen + plen + 11

        print(
            f"{self.c.WHITE}+{'-' * (slen + 2)}+{'-' * (dlen + 2)}+{'-' * (ulen + 2)}+{'-' * (plen + 2)}+"
        )

        print(
            f"{self.c.WHITE}| {self.c.BWHITE}{'Source IP'.ljust(slen)}{self.c.WHITE} | {self.c.BWHITE}{'Destination IP'.ljust(dlen)}{self.c.WHITE} | {self.c.BWHITE}{'Username'.ljust(ulen)}{self.c.WHITE} | {self.c.BWHITE}{'Password'.ljust(plen)}{self.c.WHITE} |"
        )

        print(
            f"{self.c.WHITE}+{'-' * (slen + 2)}+{'-' * (dlen + 2)}+{'-' * (ulen + 2)}+{'-' * (plen + 2)}+"
        )

        # same as rcrack: the cracked passwords only existed on screen
        if self.ofile != "":
            f = open_log(self.ofile)

        if len(self.found) == 0:
            print(f"{self.c.WHITE}| {self.c.WHITE}{'Nothing found'.ljust(tlen - 2)} |")
        else:
            for x in self.found:
                (ipsrc, ipdst, username, password) = x.split("###")

                print(
                    f"{self.c.WHITE}| {self.c.BGREEN}{ipsrc.ljust(slen)}{self.c.WHITE} | {self.c.BMAGENTA}{ipdst.ljust(dlen)}{self.c.WHITE} | {self.c.BYELLOW}{username.ljust(ulen)}{self.c.WHITE} | {self.c.BRED}{password.ljust(plen)}{self.c.WHITE} |"
                )

                if self.ofile != "":
                    f.write("%s => %s => %s/%s\n" % (ipsrc, ipdst, username, password))

        if self.ofile != "":
            f.close()

        print(
            f"{self.c.WHITE}+{'-' * (slen + 2)}+{'-' * (dlen + 2)}+{'-' * (ulen + 2)}+{'-' * (plen + 2)}+"
        )
        print(self.c.WHITE)

        print(
            f"{self.c.BWHITE}Time elapsed: {self.c.YELLOW}{str(format_time(self.totaltime))}{self.c.WHITE}"
        )
        print(self.c.WHITE)

        self.found.clear()
