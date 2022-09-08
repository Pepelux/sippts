import random
import re
import netifaces
import socket
import subprocess
import struct
import os
import hashlib
import platform

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


def screen_clear():
    # for mac and linux(here, os.name is 'posix')
    if os.name == 'posix' or os.name == 'Linux':
        _ = os.system('clear')
    else:
        # for windows platfrom
        _ = os.system('cls')


def get_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 0))
    _, port = sock.getsockname()
    sock.close()

    return port


def ping(host, time='1'):
    # parameter = '-n' if platform.system().lower() == 'windows' else '-c'
    ping = 'ping -t 1 -c 1 -W %s %s >/dev/null' % (time, host)
    response = os.system(ping)

    if response == 0:
        return True
    else:
        return False


def get_machine_default_ip(type='ip'):
    """Return the default gateway IP for the machine."""
    gateways = netifaces.gateways()
    defaults = gateways.get("default")
    if not defaults:
        return

    def default_ip(family):
        gw_info = defaults.get(family)
        if not gw_info:
            return
        addresses = netifaces.ifaddresses(gw_info[1]).get(family)
        if addresses:
            if type == 'mask':
                return addresses[0]["netmask"]
            else:
                return addresses[0]["addr"]

    return default_ip(netifaces.AF_INET) or default_ip(netifaces.AF_INET6)


def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def long2ip(ip):
    return str(socket.inet_ntoa(struct.pack('!L', ip)))


def generate_random_string(len, only_hex):
    if only_hex == 0:
        result_str = ''.join(random.choice(
            '0123456789abcdefghijklmnopqqrstuvwxyz') for i in range(len))
    else:
        result_str = ''.join(random.choice('0123456789abcdef')
                             for i in range(len))

    return(result_str)


def create_message(method, contactdomain, fromuser, fromname, fromdomain, touser, toname, todomain, proto, domain, useragent, fromport, branch, callid, tag, cseq, totag, digest, referto, withsdp):
    if method == 'NOTIFY':
        starting_line = '%s sip:%s SIP/2.0' % (method, domain)
    else:
        starting_line = '%s sip:%s@%s SIP/2.0' % (method, touser, domain)

    if branch == '':
        branch = generate_random_string(71, 0)
    if callid == '':
        callid = generate_random_string(32, 1)
    if tag == '':
        tag = generate_random_string(8, 1)

    if method == 'REFER' and referto == '':
        referto = '999'

    headers = dict()
    headers['Via'] = 'SIP/2.0/%s %s:%s;branch=%s' % (
        proto.upper(), contactdomain, fromport, branch)
    headers['From'] = '%s <sip:%s@%s>;tag=%s' % (
        fromname, fromuser, fromdomain, tag)

    if method == 'NOTIFY':
        if totag == '':
            headers['To'] = '<sip:%s>' % todomain
        else:
            headers['To'] = '<sip:%s>;tag=%s' % (todomain, totag)
    else:
        if totag == '':
            headers['To'] = '%s <sip:%s@%s>' % (toname, touser, todomain)
        else:
            headers['To'] = '%s <sip:%s@%s>;tag=%s' % (
                toname, touser, todomain, totag)

    if method != 'CANCEL':
        headers['Contact'] = '<sip:%s@%s:%d;transport=%s>' % (
            fromuser, contactdomain, fromport, proto)

    headers['Call-ID'] = '%s' % callid

    if digest != '':
        headers['Authorization'] = '%s' % digest

    headers['CSeq'] = '%d %s' % (cseq, method)
    headers['Max-Forwards'] = '70'

    if method == 'REFER':
        headers['Refer-To'] = '<sip:%s@%s>' % (referto, domain)
        headers['Referred-By'] = '<sip:%s@%s:%s>' % (
            fromuser, domain, fromport)

    if method == 'SUBSCRIBE':
        headers['Accept'] = 'application/x-as-feature-event+xml'
        headers['Event'] = 'as-feature-event'

    if method == 'NOTIFY':
        headers['Event'] = 'keep-alive'

    if method != 'ACK':
        headers['User-Agent'] = '%s' % useragent
        if method != 'CANCEL':
            headers['Allow'] = 'INVITE,REGISTER,ACK,CANCEL,BYE,NOTIFY,REFER,OPTIONS,INFO,SUBSCRIBE,UPDATE,PRACK,MESSAGE'

    if method == 'REGISTER':
        headers['Expires'] = '10'

    msg = starting_line+'\r\n'
    for h in headers.items():
        msg += '%s: %s\r\n' % h

    sdp = ''
    if withsdp == 1:
        sdp = '\r\n'
        sdp += 'v=0\r\n'
        sdp += 'o=anonymous 1312841870 1312841870 IN IP4 %s\r\n' % contactdomain
        sdp += 's=session\r\n'
        sdp += 'c=IN IP4 %s\r\n' % contactdomain
        sdp += 't=0 0\r\n'
        sdp += 'm=audio 2362 RTP/AVP 0\r\n'
        sdp += 'a=rtpmap:18 G729/8000\r\n'
        sdp += 'a=rtpmap:0 PCMU/8000\r\n'
        sdp += 'a=rtpmap:8 PCMA/8000\r\n'

    msg += 'Content-Length: ' + str(len(sdp)) + '\r\n'
    msg += sdp

    msg += '\r\n'

    return(msg)


def create_response_error(message, fromuser, touser, proto, domain, fromport, cseq, method, branch, callid, tag, totag, iplocal):
    realm = 'asterisk'
    nonce = generate_random_string(8, 0)
    digest = 'Digest algorithm=MD5, realm="%s", nonce="%s\"' % (realm, nonce)

    starting_line = 'SIP/2.0 %s' % message

    headers = dict()
    headers['Via'] = 'SIP/2.0/%s %s:%s;branch=%s' % (
        proto.upper(), domain, fromport, branch)
    headers['From'] = '<sip:%s@%s>;tag=%s' % (fromuser, domain, totag)
    headers['To'] = '<sip:%s@%s>;tag=%s' % (touser, iplocal, tag)
    headers['Call-ID'] = '%s' % callid
    headers['CSeq'] = '%d %s' % (cseq, method)
    if method == 'BYE':
        headers['WWW-Authenticate'] = '%s' % digest
    headers['Content-Length'] = '0'

    msg = starting_line+'\r\n'
    for h in headers.items():
        msg += '%s: %s\r\n' % h

    msg += '\r\n'

    return(msg)


def create_response_ok(fromuser, touser, proto, domain, fromport, cseq, branch, callid, tag, totag):
    starting_line = 'SIP/2.0 200 Ok'

    headers = dict()
    headers['Via'] = 'SIP/2.0/%s %s:%s;branch=%s' % (
        proto.upper(), domain, fromport, branch)
    headers['From'] = '<sip:%s@%s>;tag=%s' % (fromuser, domain, totag)
    headers['To'] = '<sip:%s@%s>;tag=%s' % (touser, domain, tag)
    headers['Call-ID'] = '%s' % callid
    headers['CSeq'] = '%d BYE' % cseq
    headers['Content-Length'] = '0'

    msg = starting_line+'\r\n'
    for h in headers.items():
        msg += '%s: %s\r\n' % h

    msg += '\r\n'

    return(msg)


def parse_message(buffer):
    headers = buffer.split('\r\n')

    data = dict()
    data['sipuser'] = ''
    data['sipdomain'] = ''
    data['ua'] = ''

    for header in headers:
        m = re.search('^SIP\/[0-9|\.]+\s([0-9]+)\s(.+)', header)
        if m:
            data['response_code'] = '%s' % (m.group(1))
            data['response_text'] = '%s' % (m.group(2))

        m = re.search('([a-z|A-Z]+)\ssip\:(.*)\sSIP\/[0-9|\.]*', header)
        if m:
            data['method'] = '%s' % (m.group(1))
            uri = '%s' % (m.group(2))
            if uri.find('@') > 0:
                n = re.search('(.*)@(.*)', uri)
                data['sipuser'] = '%s' % (n.group(1))
                data['sipdomain'] = '%s' % (n.group(2))
            else:
                data['sipdomain'] = uri
            if data['sipdomain'].find(':') > 0:
                n = re.search('(.*):(.*)', uri)
                data['sipdomain'] = '%s' % (n.group(1))
                data['sipport'] = '%s' % (n.group(2))
            else:
                data['sipport'] = '5060'

        m = re.search('^From:\s.*\<sip:([a-z|A-z|0-9|_]*)\@.*', header)
        if m:
            data['fromuser'] = '%s' % (m.group(1))

        m = re.search('^From:\s(.+)', header)
        if m:
            hfrom = '%s' % (m.group(1))

            try:
                n = re.search('.*;tag=(.+)', hfrom)
                if n:
                    data['fromtag'] = '%s' % (n.group(1))
                else:
                    data['fromtag'] = ''
            except:
                data['fromtag'] = ''

        m = re.search('^Call-ID:\s(.*)', header)
        if m:
            data['callid'] = '%s' % (m.group(1))

        m = re.search('^Server:\s(.+)', header)
        if m:
            data['ua'] = '%s' % (m.group(1))
        else:
            m = re.search('^User-Agent:\s(.+)', header)
            if m:
                data['ua'] = '%s' % (m.group(1))

        m = re.search('^To:\s(.+)', header)
        if m:
            to = '%s' % (m.group(1))

            try:
                n = re.search('.*;tag=(.+)', to)
                if n:
                    data['totag'] = '%s' % (n.group(1))
                else:
                    data['totag'] = ''
            except:
                data['totag'] = ''

        m = re.search(
            '^Contact:\s.*\<sip:([a-z|A-z|0-9|_]*)\@([0-9|\.]*):*.*\>.*', header)
        if m:
            data['contactuser'] = '%s' % (m.group(1))
            data['contactdomain'] = '%s' % (m.group(2))

        m = re.search('^Via:\s(.+)', header)
        if m:
            via = '%s' % (m.group(1))
            n = re.search('.+;branch=(.+);*.*', via)
            if n:
                data['branch'] = '%s' % (n.group(1))
            else:
                data['branch'] = ''

        m = re.search('^Authorization:\s(.+)', header)
        if m:
            data['auth'] = '%s' % (m.group(1))
        else:
            m = re.search('^WWW-Authenticate:\s(.+)', header)
            if m:
                data['auth'] = '%s' % (m.group(1))

        m = re.search('^CSeq:\s([0-9]+)\s.*', header)
        if m:
            data['cseq'] = '%s' % (m.group(1))

    return data


def parse_digest(buffer):
    headers = buffer.split('\r\n')

    data = dict()

    data['algorithm'] = 'MD5'

    for header in headers:
        m = re.search('username=\"([a-z|A-Z|0-9|-|_]+)\"', header)
        if m:
            data['username'] = '%s' % (m.group(1))
        else:
            data['username'] = ''

        m = re.search('realm=\"([a-z|A-Z|0-9|-|_|\.]+)\"', header)
        if m:
            data['realm'] = '%s' % (m.group(1))
        else:
            data['realm'] = ''

        m = re.search('\snonce=\"([a-z|A-Z|0-9|\/|\+|\=]+)\"', header)
        if m:
            data['nonce'] = '%s' % (m.group(1))
        else:
            data['nonce'] = ''

        m = re.search('uri=\"([a-z|A-Z|0-9|-|_|\.|\:|\;|\=|\@|\#]+)\"', header)
        if m:
            data['uri'] = '%s' % (m.group(1))
        else:
            data['uri'] = ''

        m = re.search('response=\"([a-z|0-9]+)\"', header)
        if m:
            data['response'] = '%s' % (m.group(1))
        else:
            data['response'] = ''

        m = re.search('algorithm=([a-z|A-Z|0-9|-|_]+)', header)
        if m:
            data['algorithm'] = '%s' % (m.group(1))
        else:
            data['algorithm'] = 'MD5'

        m = re.search('cnonce=\"([\w\+\/]+)\"', header)
        if m:
            data['cnonce'] = '%s' % (m.group(1))
        else:
            data['cnonce'] = ''

        m = re.search('nc=\"*([\w\+]+)\"*', header)
        if m:
            data['nc'] = '%s' % (m.group(1))
        else:
            data['nc'] = ''

        m = re.search('qop=\"*([\w\+]+)\"*', header)
        if m:
            data['qop'] = '%s' % (m.group(1))
        else:
            data['qop'] = ''

    return data


def getHash(algorithm, string):
    if algorithm == 'MD5':
        hashfunc = hashlib.md5
    elif algorithm == 'SHA':
        hashfunc = hashlib.sha1
    elif algorithm == 'SHA-256':
        hashfunc = hashlib.sha256
    elif algorithm == 'SHA-512':
        hashfunc = hashlib.sha512

    return hashfunc(string.encode()).hexdigest()


def calculateHash(username, realm, pwd, method, uri, nonce, algorithm, cnonce, nc, qop, verbose, entitybody):
    # HA1 = MD5(username:realm:password)
    # HA2 = MD5(method:digestURI)
    # response = MD5(HA1:nonce:HA2)

    # If the algorithm directive's value is "MD5-sess":
    #   HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
    # If the qop directive's value is "auth-int":
    #   HA2 = MD5(method:digestURI:MD5(entityBody))
    # If the qop directive's value is "auth" or "auth-int":
    #   response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)

    a1 = '%s:%s:%s' % (username, realm, pwd)
    a2 = '%s:%s' % (method, uri)

    ha1 = getHash(algorithm, a1)
    if algorithm == 'MD5-sess':
        a1 = '%s:%s:%s' % (ha1, nonce, cnonce)
        ha1 = getHash(algorithm, a1)
    ha2 = getHash(algorithm, a2)
    if (qop == 'auth' or qop == 'auth-int') and cnonce != '':
        if entitybody != '':
            a2 = '%s:%s:%s' % (method, uri, getHash(algorithm, entitybody))
            ha2 = getHash(algorithm, a2)
        b = '%s:%s:%s:%s:%s:%s' % (ha1, nonce, nc, cnonce, qop, ha2)
    else:
        b = '%s:%s:%s' % (ha1, nonce, ha2)
    ret = getHash(algorithm, b)

    if verbose == 1:
        print(WHITE+'Calculating %s hash:' % (algorithm))
        print(WHITE+'A1 hash %s(%s): %s' % (algorithm, a1, ha1))
        print(WHITE+'A2 hash %s(%s): %s' % (algorithm, a2, ha2))
        print(WHITE+'B  hash %s(%s): %s' % (algorithm, b, ret))
        print(WHITE)
    return ret
