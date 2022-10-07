#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__version__ = '3.2'
__license__ = "GPL"
__copyright__ = "Copyright (C) 2015-2022, SIPPTS"
__email__ = "pepeluxx@gmail.com"

from curses.ascii import isascii
import io
import base64
from nis import cat
# from string import printable
# from itertools import product, count
import re
from lib.functions import calculateHash
import itertools
import string
import threading
import signal
from lib.color import Color


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

        self.found = []

        self.c = Color()

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
        print(self.c.BYELLOW + '\nPress Ctrl+C to stop\n')
        print(self.c.WHITE)

        threads = list()
        t = threading.Thread(target=self.read_data, daemon=True)
        threads.append(t)
        t.start()
        t.join()

        self.found.sort()
        self.print()

    def signal_handler(self, sig, frame):
        print(self.c.BYELLOW + 'You pressed Ctrl+C!')
        print(self.c.BWHITE + '\nStopping sipcrack ...')
        print(self.c.WHITE)

        self.stop()

    def stop(self):
        self.run = False

    def read_data(self):
        # File format:
        # ipsrc"ipdst"username"realm"method"uri"nonce"cnonce"nc"qop"auth"response

        with open(self.file) as f:
            if self.run == True:
                line = f.readline()

                print(self.c.BWHITE + '[!]' + self.c.WHITE + ' Using wordlist: ' +
                      self.c.GREEN + '%s' % self.wordlist + self.c.WHITE)
                print(self.c.BWHITE + '[!]' + self.c.WHITE + ' Hashes file: ' +
                      self.c.GREEN + '%s' % self.file + self.c.WHITE)

                rows = []

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

                    row = '%s#%s#%s#%s' % (ipsrc, ipdst, username, realm)

                    if row in rows:
                        print(self.c.YELLOW + 'username %s@%s already checked' %
                              (username, ipdst) + self.c.WHITE)
                    else:
                        print(self.c.BYELLOW+'[+] Trying to crack hash %s of the user %s ...' %
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
                            print(self.c.GREEN+'[-] Cleartext password for user %s is %s' %
                                  (username, pwd))
                            self.found.append('%s###%s###%s###%s' % (
                                ipsrc, ipdst, username, pwd))
                        else:
                            print(
                                self.c.RED+'[-] Password not found. Try with another wordlist')

                    rows.append(row)
                    line = f.readline()
            else:
                f.close()
                return

        f.close()

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

        print(self.c.WHITE + '\nSaving restore data ...')

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
                    if self.run == False:
                        return ''

                    xs = itertools.product(self.chars, repeat=n)
                    combos = itertools.islice(xs, START_VALUE, None)

                    for i, pwd in enumerate(combos, start=START_VALUE):
                        if self.run == False:
                            return ''

                        pwd = ''.join(pwd)
                        pwd = '%s%s%s' % (self.prefix, pwd, self.suffix)
                        pwd = pwd.replace('\n', '')

                        print(self.c.BWHITE + '   [-] Trying pass ' +
                              self.c.YELLOW + '%s' % pwd + self.c.WHITE, end="\r")

                        if word_start == '' or word_start == pwd:
                            word_start = ''
                            if self.verbose == 1:
                                print(self.c.WHITE+'Password: %s' % pwd)
                                print(self.c.WHITE+'Expected hash: %s' %
                                      response)
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
            with open(self.wordlist, 'rb') as fd:
                pwd = '#'
                while pwd != '':
                    if self.run == False:
                        return ''

                    try:
                        pwd = fd.readline()

                        try:
                            x = pwd.decode('ascii')
                            isascii = 1
                        except:
                            isascii = 0
                            pwd = '#'

                        pwd = pwd.decode()
                        pwd = pwd.replace('\'', '')
                        pwd = pwd.replace('"', '')
                        pwd = pwd.replace('<', '')
                        pwd = pwd.replace('>', '')

                        try:
                            m = re.search('^\n$', pwd.replace(' ', ''))
                            if m:
                                pwd = '#'
                        except:
                            pass

                        pwd = pwd.replace('\n', '')
                        pwd = pwd.strip()
                        pwd = pwd[0:50]

                        if pwd != '' and pwd != '#' and isascii == 1:
                            print(
                                self.c.BWHITE + '   [-] Trying pass ' + self.c.YELLOW + '%s'.ljust(50) % pwd + self.c.WHITE, end="\r")

                            if word_start == '' or word_start == pwd:
                                word_start = ''
                                if self.verbose == 1:
                                    print(self.c.WHITE+'Password: %s' %
                                          pwd.ljust(50))
                                    print(self.c.WHITE+'Expected hash: %s' %
                                          (response))
                                if response == calculateHash(username, realm, pwd, method, uri, nonce, algorithm, cnonce, nc, qop, self.verbose, ''):
                                    fd.close()
                                    self.save_file(
                                        self.wordlist, username, pwd)
                                    return pwd
                    except KeyboardInterrupt:
                        fd.close()
                        self.save_file(self.wordlist, username, pwd)
                        self.run = False
                        self.stop()
                        return ''
                    except:
                        pass

            self.save_file(self.wordlist, username, pwd)
            fd.close()
            return ''

        self.save_file(self.wordlist, username, pwd)
        return ''

    def print(self):
        slen = len('Source IP')
        dlen = len('Destination IP')
        ulen = len('Username')
        plen = len('Password')

        for x in self.found:
            (s, d, u, p) = x.split('###')
            if len(s) > slen:
                slen = len(s)
            if len(d) > dlen:
                dlen = len(d)
            if len(u) > ulen:
                ulen = len(u)
            if len(p) > plen:
                plen = len(p)

        tlen = slen+dlen+ulen+plen+11

        print(self.c.WHITE + '\n ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'Source IP'.ljust(slen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Destination IP'.ljust(dlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Username'.ljust(ulen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Password'.ljust(plen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (ip, port, proto, res) = x.split('###')

                if res == 'No Auth Digest received :(':
                    colorres = self.c.RED
                else:
                    colorres = self.c.BLUE

                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(slen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % port.ljust(dlen) + self.c.WHITE +
                      ' | ' + self.c.YELLOW + '%s' % proto.ljust(ulen) + self.c.WHITE +
                      ' | ' + colorres + '%s' % res.ljust(plen) + self.c.WHITE + ' |')

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        self.found.clear()
