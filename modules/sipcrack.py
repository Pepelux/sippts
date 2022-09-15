#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.1.1'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

import io
import base64
from string import printable
from itertools import product, count
from lib.functions import calculateHash
import itertools
import string
import threading
import signal

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


class SipDigestCrack:
    def __init__(self):
        self.file = '-'
        self.wordlist = ''
        self.username = ''
        self.bruteforce = 'False'
        self.charset = 'printable'
        self.min = '1'
        self.max = '8'
        self.prefix = ''
        self.suffix = ''
        self.verbose = '0'

        self.run = True

    def start(self):
        if self.charset == 'digits':
            self.chars = string.digits
        elif self.charset == 'ascii_letters':
            self.chars = string.ascii_letters
        elif self.charset == 'ascii_lowercase':
            self.chars = string.ascii_lowercase
        elif self.charset == 'ascii_uppercase':
            self.chars = string.ascii_uppercase
        elif self.charset == 'hexdigits':
            self.chars = string.hexdigits
        elif self.charset == 'octdigits':
            self.chars = string.octdigits
        elif self.charset == 'punctuation':
            self.chars = string.punctuation
        elif self.charset == 'printable':
            self.chars = string.printable
        elif self.charset == 'whitespace':
            self.chars = string.whitespace
        else:
            self.chars = self.charset

        if self.bruteforce == 1:
            self.bruteforce = 'True'

        signal.signal(signal.SIGINT, self.signal_handler)
        print(BYELLOW + '\nPress Ctrl+C to stop\n')
        print(WHITE)

        threads = list()
        t = threading.Thread(target=self.read_data, daemon=True)
        threads.append(t)
        t.start()
        t.join()

    def signal_handler(self, sig, frame):
        print(BYELLOW + 'You pressed Ctrl+C!')
        print(BWHITE + '\nStopping sipcrack ...')
        print(WHITE)

        self.stop()

    def stop(self):
        self.run = False

    def read_data(self):
        # File format:
        # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response

        try:
            with open(self.file) as f:
                if self.run == True:
                    line = f.readline()

                    print(BWHITE + '[!]' + WHITE + ' Using wordlist: ' +
                          GREEN + '%s' % self.wordlist + WHITE)
                    print(BWHITE + '[!]' + WHITE + ' Hashes file: ' +
                          GREEN + '%s' % self.file + WHITE)

                    while line:
                        if self.run == False:
                            f.close()
                            return
                        line = line.replace('\n', '')
                        values = line.split('"')

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

                        print(BYELLOW+'[+] Trying to crack hash %s of the user %s ...' %
                              (response, username))

                        word_start = ''

                        try:
                            with io.open("sipcrack.res", "r", newline=None, encoding="latin-1") as fd:
                                for pline in fd:
                                    try:
                                        pl = pline.replace('\n', '')
                                        # type (bf|wl) - chars - prefix - suffix - username - b64(starting_password)
                                        values = pl.split(':')
                                        if ((self.bruteforce != 'True' and values[0] == 'wl' and values[1] == self.wordlist and self.prefix == values[2] and self.suffix == values[3]) or
                                                (self.bruteforce == 'True' and values[0] == 'bf' and values[1] == self.chars and self.prefix == values[2] and self.suffix == values[3])) and values[4] == username:
                                            b64pwd = base64.b64decode(
                                                values[5]).decode()
                                            word_start = b64pwd
                                    except:
                                        fd.close()
                                        return ''

                            fd.close()
                        except:
                            pass

                        pwd = self.crack(response, username, realm, method,
                                         uri, nonce, algorithm, cnonce, nc, qop, word_start)

                        if pwd != '':
                            print(GREEN+'[-] Cleartext password for user %s is %s' %
                                  (username, pwd))
                        else:
                            print(
                                RED+'[-] Password not found. Try with another wordlist')

                        line = f.readline()
                else:
                    f.close()
                    return

            f.close()
        except:
            print(RED + '%s: File not found or incorrect format\n' %
                  self.file + WHITE)

        exit()

    def check_value(self, password, chars):
        pos = len(chars)
        value = 0
        for i, c in enumerate(reversed(password)):
            value += (pos**i) * chars.index(c)
        return value

    def save_file(self, wl, usr, pwd):
        lines = []
        found = 0

        b64pwd = base64.b64encode(bytes(pwd, 'utf-8')).decode()

        print(WHITE + '\nSaving restore data ...')

        try:
            with io.open("sipcrack.res", "r", newline=None, encoding="latin-1") as fd:
                for pline in fd:
                    try:
                        pl = pline.replace('\n', '')
                        values = pl.split(':')
                        if self.bruteforce != 'True' and values[0] == 'wl' and values[1] == wl and values[2] == self.prefix and values[3] == self.suffix and values[4] == usr:
                            pl = 'wl:%s:%s:%s:%s:%s' % (
                                wl, self.prefix, self.suffix, usr, b64pwd)
                            found = 1
                        if self.bruteforce == 'True' and values[0] == 'bf' and values[1] == self.charset and values[2] == self.prefix and values[3] == self.suffix and values[4] == usr:
                            pl = 'bf:%s:%s:%s:%s:%s' % (
                                self.charset, self.prefix, self.suffix, usr, b64pwd)
                            found = 1
                        lines.append(pl)
                    except:
                        fd.close()
                        return ''

            fd.close()
        except:
            if self.bruteforce != 'True':
                pl = 'wl:%s:%s:%s:%s:%s' % (
                    wl, self.prefix, self.suffix, usr, b64pwd)
            else:
                pl = 'bf:%s:%s:%s:%s:%s' % (
                    self.charset, self.prefix, self.suffix, usr, b64pwd)
            found = 1
            lines.append(pl)

        if found == 0:
            if self.bruteforce != 'True':
                pl = 'wl:%s:%s:%s:%s:%s' % (
                    wl, self.prefix, self.suffix, usr, b64pwd)
            else:
                pl = 'bf:%s:%s:%s:%s:%s' % (
                    self.charset, self.prefix, self.suffix, usr, b64pwd)
            lines.append(pl)

        with open('sipcrack.res', 'w+') as f:
            for l in lines:
                f.write(l+'\n')

        f.close()

    def crack(self, response, username, realm, method, uri, nonce, algorithm, cnonce, nc, qop, word_start):
        if self.bruteforce == 'True':
            if self.run == False:
                return ''

            try:
                START_VALUE = self.check_value(word_start, self.chars)

                for n in range(int(self.min), int(self.max)+1):
                    xs = itertools.product(self.chars, repeat=n)
                    combos = itertools.islice(xs, START_VALUE, None)

                    for i, pwd in enumerate(combos, start=START_VALUE):
                        pwd = ''.join(pwd)
                        pwd = '%s%s%s' % (self.prefix, pwd, self.suffix)
                        pwd = pwd.replace('\n', '')

                        print(BWHITE + '   [-] Trying pass ' +
                              YELLOW + '%s' % pwd + WHITE, end="\r")

                        if word_start == '' or word_start == pwd:
                            word_start = ''
                            if self.verbose == 1:
                                print(WHITE+'Password: %s' % pwd)
                                print(WHITE+'Expected hash: %s' % response)
                            if response == calculateHash(username, realm, pwd, method, uri, nonce, algorithm, cnonce, nc, qop, self.verbose, ''):
                                self.save_file(self.wordlist, username, pwd)
                                return pwd
            except KeyboardInterrupt:
                self.save_file(self.charset, username, pwd)
                self.run = False
                self.stop()
                return ''
            except:
                pass
        else:
            with io.open(self.wordlist, "r", newline=None, encoding="latin-1") as fd:
                for line in fd:
                    if self.run == False:
                        return ''

                    try:
                        pwd = line.replace('\n', '')
                        pwd = pwd.replace('\'', '')
                        pwd = pwd.replace('"', '')
                        pwd = pwd.replace('<', '')
                        pwd = pwd.replace('>', '')
                        pwd = pwd.strip()
                        pwd = pwd[0:50]

                        # only check ascii
                        # pwd = ascii(pwd)

                        print(
                            BWHITE + '   [-] Trying pass ' + YELLOW + '%s'.ljust(50) % pwd + WHITE, end="\r")

                        if word_start == '' or word_start == pwd:
                            word_start = ''
                            if self.verbose == 1:
                                print(WHITE+'Password: %s' % (pwd))
                                print(WHITE+'Expected hash: %s' % (response))
                            if response == calculateHash(username, realm, pwd, method, uri, nonce, algorithm, cnonce, nc, qop, self.verbose, ''):
                                fd.close()
                                self.save_file(self.wordlist, username, pwd)
                                return pwd
                    except KeyboardInterrupt:
                        fd.close()
                        self.save_file(self.wordlist, username, pwd)
                        self.run = False
                        self.stop()
                        return ''
                    except:
                        fd.close()
                        self.save_file(self.wordlist, username, pwd)
                        return ''

            fd.close()

        self.save_file(self.wordlist, username, pwd)
        return ''
