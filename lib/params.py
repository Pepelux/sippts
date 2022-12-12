import sys
import argparse

BRED = '\033[1;31;20m'
RED = '\033[0;31;20m'
BRED_BLACK = '\033[1;30;41m'
RED_BLACK = '\033[0;30;41m'
BGREEN = '\033[1;32;20m'
GREEN = '\033[0;32;20m'
BGREEN_BLACK = '\033[1;30;42m'
GREEN_BLACK = '\033[0;30;42m'
BYELLOW = '\033[1;33;20m'
YELLOW = '\033[0;33;20m'
BBLUE = '\033[1;34;20m'
BLUE = '\033[0;34;20m'
BMAGENTA = '\033[1;35;20m'
MAGENTA = '\033[0;35;20m'
BCYAN = '\033[1;36;20m'
CYAN = '\033[0;36;20m'
BWHITE = '\033[1;37;20m'
WHITE = '\033[0;37;20m'


def get_sipscan_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─██─███─▄▄▄███▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= Fast SIP scanner =-''' + WHITE,
        epilog=BWHITE + '''
Fast SIP scanner using multithread. Sipscan can check several IPs and port ranges. It works with 
UDP, TCP and TLS protocols.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24)', dest="ipaddr")
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--remote_port', type=str, help='Ports to scan. Ex: 5060 | 5070,5080 | 5060-5080 | 5060,5062,5070-5080 | ALL for 1-65536 (default: 5060)', dest='remote_port', default='5060')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls|all (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='Method used to scan: options, invite, register (default: options)', dest='method', default='options')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 200)', dest='threads', default=200)
    parser.add_argument('-ping', help='Ping host before scan', dest='ping', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-f', '--file', type=str, help='File with several IPs or network ranges', dest='file', default='')
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")
    parser.add_argument('-o', '--output_file', type=str, help='Save data into a log file', dest='ofile', default='')
    parser.add_argument('-fp', help='Try to fingerprinting', dest='fp', action="count")
    parser.add_argument('-random', help='Randomize target hosts', dest='random', action="count")
    parser.add_argument('-ppi', type=str, help='P-Preferred-Identity', dest='ppi', default='')
    parser.add_argument('-pai', type=str, help='P-Asserted-Identity', dest='pai', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.ipaddr and not args.file:
        print(
            'error: one of the following arguments are required: -i/--ip, -f/--file')
        sys.exit()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        PORT = args.remote_port
        PROTO = args.proto
        METHOD = args.method
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        FROMDOMAIN = args.from_domain
        TONAME = args.to_name
        TOUSER = args.to_user
        TODOMAIN = args.to_domain
        UA = args.user_agent
        THREADS = args.threads
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        PING = args.ping
        FILE = args.file
        NOCOLOR = args.nocolor
        OFILE = args.ofile
        FP = args.fp
        RANDOM = args.random
        PPI = args.ppi
        PAI = args.pai

        return IPADDR, HOST, PROXY, PORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, UA, THREADS, VERBOSE, PING, FILE, NOCOLOR, OFILE, FP, RANDOM, PPI, PAI
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipexten_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

███████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄─█▄─▀─▄█─▄─▄─█▄─▄▄─█▄─▀█▄─▄█
█▄▄▄▄─██─███─▄▄▄████─▄█▀██▀─▀████─████─▄█▀██─█▄▀─██
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄█▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Identify extensions on a PBX =-''' + WHITE,
        epilog=BWHITE + '''
Identifies extensions on a SIP server. Also tells you if the extension line requires authentication 
or not. Sipexten uses multithread and can check several IPs and port ranges.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='remote_port', default=5060)
    parser.add_argument('-e', '--exten', type=str, help='Extensions to scan. Ex: 100 | 100,102,105 | 100-200 | 100,102,200-300 (default: 100-300)', dest='exten', default='100-300')
    parser.add_argument('-pr', '--prefix', type=str, help='Prefix for extensions, used for authentication', dest='prefix', default='')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='Method used to scan: options, invite, register (default: register)', dest='method', default='register')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 200)', dest='threads', default=200)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-o', '--output_file', type=str, help='Save data into a log file', dest='ofile', default='')
    parser.add_argument('-f', '--filter', help='Filter response code (ex: 200)', dest='filter', default='')
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.remote_port
        EXTEN = args.exten
        PREFIX = args.prefix
        PROTO = args.proto
        METHOD = args.method
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMUSER = args.from_user
        UA = args.user_agent
        THREADS = args.threads
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        NOCOLOR = args.nocolor
        FILTER = args.filter
        OFILE = args.ofile

        return IPADDR, HOST, PROXY, RPORT, EXTEN, PREFIX, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMUSER, UA, THREADS, VERBOSE, NOCOLOR, OFILE, FILTER
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipremotecrack_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

████████████████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄▀█▄─▄▄─█▄─▀█▀─▄█─▄▄─█─▄─▄─█▄─▄▄─███─▄▄▄─█▄─▄▄▀██▀▄─██─▄▄▄─█▄─█─▄█
█▄▄▄▄─██─███─▄▄▄████─▄─▄██─▄█▀██─█▄█─██─██─███─████─▄█▀███─███▀██─▄─▄██─▀─██─███▀██─▄▀██
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▄▄▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀▀▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Remote password cracker =-''' + WHITE,
        epilog=BWHITE + '''
A password cracker making use of digest authentication. Sipcrack uses multithread and can test 
passwords for several users using bruteforce.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='remote_port', default=5060)
    parser.add_argument('-e', '--exten', type=str, help='Extensions to attack. Ex: 100 | 100,102,105 | 100-200 | 100,102,200-300', dest='exten', required=True)
    parser.add_argument('-au', '--auth-user', type=str, help='Use a custom SIP Auth User instead the extension', dest='authuser', default="")
    parser.add_argument('-pr', '--prefix', type=str, help='Prefix for auth user, used for authentication', dest='prefix', default='')
    parser.add_argument('-l', '--lenght', type=str, help='Lenght of the extensions (if set, left padding with 0\'s)', dest='lenght', default='')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-w', '--wordlist', help='Wordlist for bruteforce', dest='wordlist', default="", required=True)
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 100)', dest='threads', default=100)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.remote_port
        EXTEN = args.exten
        PREFIX = args.prefix
        AUTHUSER = args.authuser
        LENGHT = args.lenght
        PROTO = args.proto
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        UA = args.user_agent
        WORDLIST = args.wordlist
        THREADS = args.threads
        VERBOSE = args.verbose
        NOCOLOR = args.nocolor

        return IPADDR, HOST, PROXY, RPORT, EXTEN, PREFIX, AUTHUSER, LENGHT, PROTO, DOMAIN, CONTACTDOMAIN, UA, WORDLIST, THREADS, VERBOSE, NOCOLOR
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipdigestleak_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████▀█████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄▀█▄─▄█─▄▄▄▄█▄─▄▄─█─▄▄▄▄█─▄─▄─███▄─▄███▄─▄▄─██▀▄─██▄─█─▄█
█▄▄▄▄─██─███─▄▄▄████─██─██─██─██▄─██─▄█▀█▄▄▄▄─███─██████─██▀██─▄█▀██─▀─███─▄▀██
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▀▄▄▄▀▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Exploit the SIP Digest Leak vulnerability =-''' + WHITE,
        epilog=BWHITE + '''
The SIP Digest Leak is a vulnerability that affects a large number of SIP Phones, including both hardware 
and software IP Phones as well as phone adapters (VoIP to analogue). The vulnerability allows leakage of 
the Digest authentication response, which is computed from the password. An offline password attack is then 
possible and can recover most passwords based on the challenge response.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24)', dest="ipaddr", default='')
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-o', '--output_file', type=str, help='Save digest to file in SipCrack format', dest='ofile', default='')
    parser.add_argument('-local-ip', type=str, help='Set local IP address (by default try to get it)', dest='localip', default='')
    parser.add_argument('-user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('-pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-auth', type=str, help='Authentication mode [www|proxy] (default: www)', dest='auth', default='www')
    parser.add_argument('-sdp', help='Send SDP in INVITE messages', dest='sdp', action="count")
    parser.add_argument('-sdes', help='Send SDES in SDP', dest='sdes', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-f', '--file', type=str, help='File with several IPs (format: ip:port/proto ... one per line)', dest='file', default='')
    parser.add_argument('-l', '--log_file', type=str, help='Save result into a file', dest='lfile', default='')
    parser.add_argument('-ping', help='Ping host before send attack', dest='ping', action="count")
    parser.add_argument('-ppi', type=str, help='P-Preferred-Identity', dest='ppi', default='')
    parser.add_argument('-pai', type=str, help='P-Asserted-Identity', dest='pai', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.ipaddr and not args.file:
        print(
            'error: one of the following arguments are required: -i/--ip, -f/--file')
        sys.exit()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.rport
        PROTO = args.proto
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        FROMDOMAIN = args.from_domain
        TONAME = args.to_name
        TOUSER = args.to_user
        TODOMAIN = args.to_domain
        UA = args.user_agent
        OFILE = args.ofile
        LFILE = args.lfile
        LOCALIP = args.localip
        USER = args.user
        PWD = args.pwd
        AUTH = args.auth
        SDP = args.sdp
        SDES = args.sdes
        VERBOSE = args.verbose
        FILE = args.file
        PING = args.ping
        PPI = args.ppi
        PAI = args.pai

        return IPADDR, HOST, PROXY, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, UA, LOCALIP, OFILE, LFILE, USER, PWD, AUTH, VERBOSE, SDP, SDES, FILE, PING, PPI, PAI
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipinvite_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄█▄─▀█▄─▄█▄─█─▄█▄─▄█─▄─▄─█▄─▄▄─█
█▄▄▄▄─██─███─▄▄▄████─███─█▄▀─███▄▀▄███─████─████─▄█▀█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▀▄▄▄▀▀▄▄▀▀▀▄▀▀▀▄▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= SIP Invite attack =-''' + WHITE,
        epilog=BWHITE + '''
Checks if a server allow us to make calls without authentication. If the SIP server has a bad 
configuration, it will allow us to make calls to external numbers. Also it can allow us to transfer 
the call to a second external number.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-l', '--local_port', type=int, help='Local port (default: first free)', dest='lport')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from-user', type=str, help='Origin numbers to call (From). Ex: 100 | 100,102,105 | 100000000-199999999', dest="from_user", default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to-user', type=str, help='Destination numbers to call (To). Ex: 100 | 100,102,105 | 100000000-199999999', dest="to_user", default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-t', '--transfer', type=str, help='Phone number to transfer the call', dest='transfer_number', default='')
    parser.add_argument('-user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('-pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-local-ip', type=str, help='Set local IP address (by default try to get it)', dest='localip', default='')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 200)', dest='threads', default=200)
    parser.add_argument('-no-sdp', help='Do not send SDP (by default is included)', dest='nosdp', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-sdes', help='Use SDES in SDP protocol', dest='sdes', action="count")
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")
    parser.add_argument('-o', '--output_file', type=str, help='Save data into a log file', dest='ofile', default='')
    parser.add_argument('-ppi', type=str, help='P-Preferred-Identity', dest='ppi', default='')
    parser.add_argument('-pai', type=str, help='P-Asserted-Identity', dest='pai', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.rport
        LPORT = args.lport
        PROTO = args.proto
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        FROMDOMAIN = args.from_domain
        TONAME = args.to_name
        TOUSER = args.to_user
        TODOMAIN = args.to_domain
        TRANSFER = args.transfer_number
        USER = args.user
        PWD = args.pwd
        UA = args.user_agent
        LOCALIP = args.localip
        THREADS = args.threads
        NOSDP = args.nosdp
        VERBOSE = args.verbose
        SDES = args.sdes
        NOCOLOR = args.nocolor
        OFILE = args.ofile
        PPI = args.ppi
        PAI = args.pai

        return IPADDR, HOST, PROXY, RPORT, LPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, TRANSFER, USER, PWD, UA, LOCALIP, THREADS, NOSDP, VERBOSE, SDES, NOCOLOR, OFILE, PPI, PAI
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipcrack_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████▀███████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄▀█▄─▄█─▄▄▄▄█▄─▄▄─█─▄▄▄▄█─▄─▄─███─▄▄▄─█▄─▄▄▀██▀▄─██─▄▄▄─█▄─█─▄█
█▄▄▄▄─██─███─▄▄▄████─██─██─██─██▄─██─▄█▀█▄▄▄▄─███─█████─███▀██─▄─▄██─▀─██─███▀██─▄▀██
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▀▄▄▄▀▀▀▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= SIP digest authentication cracking =-''' + WHITE,
        epilog=BWHITE + '''Bruteforce charsets
-------------------
alphabet=ascii_letters    # The ascii_lowercase and ascii_uppercase constants
alphabet=ascii_lowercase  # The lowercase letters: abcdefghijklmnopqrstuvwxyz
alphabet=ascii_uppercase  # The uppercase letters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
alphabet=digits           # The string: 0123456789
alphabet=hexdigits        # The string: 0123456789abcdefABCDEF
alphabet=octdigits        # The string: 01234567
alphabet=punctuation      # String of ASCII characters: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
alphabet=printable        # Combination of digits, ascii_letters, punctuation, and whitespace
alphabet=whitespace       # This includes the characters space, tab, linefeed, return, formfeed, and vertical tab
alphabet=0123456789abcdef # Custom alphabet

''' + BWHITE + '''SIP Digest Crack is a tool to crack the digest authentications within the SIP protocol. ''' + WHITE + '''
 
''')

    # Add arguments
    parser.add_argument('-w', '--wordlist', help='Wordlist for bruteforce', dest='wordlist', default="")
    parser.add_argument('-bf', '--bruteforce', help='Bruteforce password', dest='bruteforce', action="count")
    parser.add_argument('-p' , '--prefix', type=str, help='Prefix for passwords', dest='prefix', default='')
    parser.add_argument('-s' , '--suffix', type=str, help='Suffix for passwords', dest='suffix', default='')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-f', '--file', type=str, help='SipCrack format file with SIP Digest hashes', dest='file', default="", required=True)
    parser.add_argument('-charset', help='Charset for bruteforce (default: printable)', dest='charset', default='printable')
    parser.add_argument('-min', '--min_length', type=int, help='Min length for bruteforce (default: 1)', dest='min', default=1)
    parser.add_argument('-max', '--max_length', type=int, help='Max length for bruteforce (default: 8)', dest='max', default=8)

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.bruteforce and not args.wordlist:
        print(
            'error: one of the following arguments are required: -bf/--bruteforce, -w/--wordlist')
        sys.exit()

    try:
        FILE = args.file
        WORDLIST = args.wordlist
        BRUTEFORCE = args.bruteforce
        MAX=args.max
        MIN=args.min
        CHARSET=args.charset
        PREFIX=args.prefix
        SUFFIX=args.suffix
        VERBOSE = args.verbose

        return FILE, VERBOSE, WORDLIST, BRUTEFORCE, CHARSET, MAX, MIN, PREFIX, SUFFIX
    except ValueError:
        print('[-] Error')
        sys.exit(1)


def get_sipsend_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███─▄▄▄▄█▄─▄▄─█▄─▀█▄─▄█▄─▄▄▀█
█▄▄▄▄─██─███─▄▄▄███▄▄▄▄─██─▄█▀██─█▄▀─███─██─█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Send a customized message =-''' + WHITE,
        epilog=BWHITE + '''
SIP Send allow us to send a customized SIP message and analyze the response.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-l', '--local_port', type=int, help='Local port (default: first free)', dest='lport')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='SIP Method: options|invite|register|subscribe|cancel|bye|...', dest='method', required=True)
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-ft', '--from_tag', type=str, help='From Tag', dest='from_tag', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-tt', '--to_tag', type=str, help='To Tag', dest='to_tag', default='')
    parser.add_argument('-user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('-pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-digest', type=str, help='Add a customized Digest header', dest='digest', default='')
    parser.add_argument('-branch', type=str, help='Customize Branch header', dest='branch', default='')
    parser.add_argument('-cid', '--callid', type=str, help='Customize CallID header', dest='callid', default='')
    parser.add_argument('-cseq', type=str, help='Customize Seq number', dest='cseq', default='')
    parser.add_argument('-sdp', help='Include SDP', dest='sdp', action="count")
    parser.add_argument('-sdes', help='Use SDES in SDP protocol', dest='sdes', action="count")
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-local-ip', type=str, help='Set local IP address (by default try to get it)', dest='localip', default='')
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")
    parser.add_argument('-o', '--output_file', type=str, help='Save data into a log file', dest='ofile', default='')
    parser.add_argument('-ppi', type=str, help='P-Preferred-Identity', dest='ppi', default='')
    parser.add_argument('-pai', type=str, help='P-Asserted-Identity', dest='pai', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    HOST = args.ipaddr
    PROXY = args.proxy
    RPORT = args.rport
    LPORT = args.lport
    PROTO = args.proto
    METHOD = args.method
    DOMAIN = args.domain
    CONTACTDOMAIN = args.contact_domain
    FROMNAME = args.from_name
    FROMUSER = args.from_user
    FROMDOMAIN = args.from_domain
    FROMTAG = args.from_tag
    TONAME = args.to_name
    TOUSER = args.to_user
    TOTAG = args.to_tag
    TODOMAIN = args.to_domain
    USER = args.user
    PWD = args.pwd
    DIGEST = args.digest
    BRANCH = args.branch
    CALLID = args.callid
    CSEQ = args.cseq
    SDP = args.sdp
    SDES = args.sdes
    UA = args.user_agent
    LOCALIP = args.localip
    NOCOLOR = args.nocolor
    OFILE = args.ofile
    PPI = args.ppi
    PAI = args.pai

    return IPADDR, HOST, PROXY, RPORT, LPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, FROMTAG, TONAME, TOUSER, TODOMAIN, TOTAG, USER, PWD, DIGEST, BRANCH, CALLID, CSEQ, SDP, SDES, UA, LOCALIP, NOCOLOR, OFILE, PPI, PAI


def get_sipenumerate_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

██████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄─█▄─▀█▄─▄█▄─██─▄█▄─▀█▀─▄█▄─▄▄─█▄─▄▄▀██▀▄─██─▄─▄─█▄─▄▄─█
█▄▄▄▄─██─███─▄▄▄████─▄█▀██─█▄▀─███─██─███─█▄█─███─▄█▀██─▄─▄██─▀─████─████─▄█▀█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Enumerate methods =-''' + WHITE,
        epilog=BWHITE + '''
Enumerate available methods of a SIP service/server.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp\tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.rport
        PROTO = args.proto
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        FROMDOMAIN = args.from_domain
        TONAME = args.to_name
        TOUSER = args.to_user
        TODOMAIN = args.to_domain
        UA = args.user_agent
        VERBOSE = args.verbose

        return IPADDR, HOST, PROXY, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, UA, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipdump_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

██████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄▀█▄─██─▄█▄─▀█▀─▄█▄─▄▄─█
█▄▄▄▄─██─███─▄▄▄████─██─██─██─███─█▄█─███─▄▄▄█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▀▄▄▄▀▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= SIP Dump =-''' + WHITE,
        epilog=BWHITE + '''
Extracts SIP Digest authentications from a PCAP file
 
''')

    # Add arguments
    parser.add_argument('-f', '--file', type=str, help='PCAP file to analyze', dest="file", required=True, default='')
    parser.add_argument('-o', '--output_file', type=str, help='Save digest to file in SipCrack format', dest='ofile', required=True, default='')
 
    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        FILE = args.file
        OFILE = args.ofile

        return FILE, OFILE
    except ValueError:
        print('[-] Error')
        sys.exit(1)


def get_sipflood_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

███████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄─█▄─▄███─▄▄─█─▄▄─█▄─▄▄▀█
█▄▄▄▄─██─███─▄▄▄████─▄████─██▀█─██─█─██─██─██─█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▀▄▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Flood a SIP method =-''' + WHITE,
        epilog=BWHITE + '''
SIP Flood send messages with a selected method
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='SIP Method: options|invite|register|subscribe|cancel|bye|...', dest='method', default='')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-digest', type=str, help='Digest', dest='digest', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 200)', dest='threads', default=200)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-n', '--number', type=int, help='Number of requests (by default: non stop)', dest='number', default=0)
    parser.add_argument('-b', '--bad_headers', help='Send malformed headers', dest='bad', action="count")
    parser.add_argument('-a', '--alphabet', help='Alphabet [all|printable|ascii|hex] (by default: printable characters) -  "-b required"', dest="alphabet", default="printable")
    parser.add_argument('-min', type=int, help='Min length (default: 0) -  "-b required"', dest='min', default=0)
    parser.add_argument('-max', type=int, help='Max length (default: 1000) - "-b required"', dest='max', default=1000)

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        RPORT = args.rport
        PROTO = args.proto
        METHOD = args.method
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        FROMDOMAIN = args.from_domain
        TONAME = args.to_name
        TOUSER = args.to_user
        TODOMAIN = args.to_domain
        DIGEST = args.digest
        UA = args.user_agent
        THREADS = args.threads
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        NUMBER= args.number
        BAD = args.bad
        ALPHABET = args.alphabet
        MIN = args.min
        MAX = args.max

        return IPADDR, HOST, RPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, DIGEST, UA, THREADS, VERBOSE, NUMBER, BAD, ALPHABET, MAX, MIN
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_rtpbleed_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

███████████████████████████████████████████████████
█▄─▄▄▀█─▄─▄─█▄─▄▄─███▄─▄─▀█▄─▄███▄─▄▄─█▄─▄▄─█▄─▄▄▀█
██─▄─▄███─████─▄▄▄████─▄─▀██─██▀██─▄█▀██─▄█▀██─██─█
▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Detects the RTP Bleed vulnerability sending RTP streams =-''' + WHITE,
        epilog=BWHITE + '''
The RTP bleed Bug is a serious vulnerability in a number of RTP proxies. This weakness allows 
malicious users to inject and receive RTP streams of ongoing calls without needing to be positioned 
as man-in-the-middle. This may lead to eavesdropping of audio calls, impersonation and possibly cause 
toll fraud by redirecting ongoing calls.

More info about the vulnerability: https://www.rtpbleed.com/
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-s', '--start_port', type=int, help='Start port of the host (default: 10000)', dest='start_port', default=10000)
    parser.add_argument('-e', '--end_port', type=int, help='End port of the host (default: 20000)', dest='end_port', default=20000)
    parser.add_argument('-l', '--loops', type=int,help='Number of times to probe the port ranges on the target(s) (default: 4)', dest='loops', default=4)
    parser.add_argument('-p', '--payload', type=int,help='Codec payload (default: 0)', dest='payload', default=0)
    parser.add_argument('-d', '--delay', dest='delay', type=int, help='Delay for timeout in microseconds (default: 50)', default=50)

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    SP = args.start_port
    EP = args.end_port
    # Always start on odd port
    if SP % 2 != 0:
        SP = SP + 1
    if EP % 2 != 0:
        EP = EP + 1
    LOOPS = args.loops
    PAYLOAD = args.payload
    DELAY = args.delay
    return IPADDR, SP, EP, LOOPS, PAYLOAD, DELAY


def get_rtcpbleed_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████████
█▄─▄▄▀█─▄─▄─█─▄▄▄─█▄─▄▄─███▄─▄─▀█▄─▄███▄─▄▄─█▄─▄▄─█▄─▄▄▀█
██─▄─▄███─███─███▀██─▄▄▄████─▄─▀██─██▀██─▄█▀██─▄█▀██─██─█
▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Detects the RTP Bleed vulnerability sending RTCP streams =-''' + WHITE,
        epilog=BWHITE + '''
The RTP bleed Bug is a serious vulnerability in a number of RTP proxies. This weakness allows 
malicious users to inject and receive RTP streams of ongoing calls without needing to be positioned 
as man-in-the-middle. This may lead to eavesdropping of audio calls, impersonation and possibly cause 
toll fraud by redirecting ongoing calls.

More info about the vulnerability: https://www.rtpbleed.com/
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-s', '--start_port', type=int, help='Start port of the host (default: 10001)', dest='start_port', default=10001)
    parser.add_argument('-e', '--end_port', type=int, help='End port of the host (default: 20001)', dest='end_port', default=20001)
    parser.add_argument('-d', '--delay', dest='delay', type=int, help='Delay for timeout in microseconds (default: 1)', default=1)

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    SP = args.start_port
    EP = args.end_port
    # Always start on odd port
    if SP % 2 == 0:
        SP = SP + 1
    if EP % 2 == 0:
        EP = EP + 1
    DELAY = args.delay
    return IPADDR, SP, EP, DELAY


def get_rtcbleed_flood_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████████████████████████████████
█▄─▄▄▀█─▄─▄─█▄─▄▄─███▄─▄─▀█▄─▄███▄─▄▄─█▄─▄▄─█▄─▄▄▀███▄─▄▄─█▄─▄███─▄▄─█─▄▄─█▄─▄▄▀█
██─▄─▄███─████─▄▄▄████─▄─▀██─██▀██─▄█▀██─▄█▀██─██─████─▄████─██▀█─██─█─██─██─██─█
▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▀▀▀▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▀▄▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Exploit the RTP Bleed vulnerability sending RTP streams =-''' + WHITE,
        epilog=BWHITE + '''
The RTP bleed Bug is a serious vulnerability in a number of RTP proxies. This weakness allows 
malicious users to inject and receive RTP streams of ongoing calls without needing to be positioned 
as man-in-the-middle. This may lead to eavesdropping of audio calls, impersonation and possibly cause 
toll fraud by redirecting ongoing calls.

More info about the vulnerability: https://www.rtpbleed.com/
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Port number to flood', dest='port', required=True)
    parser.add_argument('-p', '--payload', type=int,help='Codec payload (default: 0)', dest='payload', default=0)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    P = args.port
    PAYLOAD = args.payload
    VERBOSE = args.verbose

    return IPADDR, P, PAYLOAD, VERBOSE


def get_rtcbleed_inject_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████████████████████████████████████████
█▄─▄▄▀█─▄─▄─█▄─▄▄─███▄─▄─▀█▄─▄███▄─▄▄─█▄─▄▄─█▄─▄▄▀███▄─▄█▄─▀█▄─▄███▄─▄█▄─▄▄─█─▄▄▄─█─▄─▄─█
██─▄─▄███─████─▄▄▄████─▄─▀██─██▀██─▄█▀██─▄█▀██─██─████─███─█▄▀─██─▄█─███─▄█▀█─███▀███─███
▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▀▀▀▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▀▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Exploit the RTP Bleed vulnerability sending RTP streams =-''' + WHITE,
        epilog=WHITE + '''
The RTP bleed Bug is a serious vulnerability in a number of RTP proxies. This weakness allows 
malicious users to inject and receive RTP streams of ongoing calls without needing to be positioned 
as man-in-the-middle. This may lead to eavesdropping of audio calls, impersonation and possibly cause 
toll fraud by redirecting ongoing calls.

More info about the vulnerability: https://www.rtpbleed.com/
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Port number to inject media', dest='port', required=True)
    parser.add_argument('-p', '--payload', type=int,help='Codec payload (default: 0)', dest='payload', default=0)
    parser.add_argument('-f', '--file', type=str, help='Audio file (WAV) to inject', dest='file', default="", required=True)

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    P = args.port
    PAYLOAD = args.payload
    FILE = args.file

    return IPADDR, P, PAYLOAD, FILE


def get_tshark_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███─▄─▄─█─▄▄▄▄█─█─██▀▄─██▄─▄▄▀█▄─█─▄█
█▄▄▄▄─██─███─▄▄▄█████─███▄▄▄▄─█─▄─██─▀─███─▄─▄██─▄▀██
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▀▄▄▄▀▀▄▄▄▄▄▀▄▀▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= TShark filters =-''' + WHITE,
        epilog=BWHITE + '''
Filters:
-------
stats               SIP packet statistics
auth                Show auth digest
messages            Show all SIP messages
frame <id>          Show a SIP message filtering by frame number
method <method>     Filter frames by method: register, invite, ...
callids             Show all call-ID
callid <cid>        Filter by call-ID
rtp                 Show all RTP streams
''' + WHITE + '''
\nPCAP manipulation with TShark.
 
''')

    # Add arguments
    parser.add_argument('-f', '--file', type=str, help='PCAP file to analyze', required=True, dest='file', default="")
    parser.add_argument('-filter', help='Filter data to show', dest='filter', default="")
    parser.add_argument('-rtp_extract', help='Extract RTP streams. Ex: -rtp_extract -r 1210 -o rtp.pcap', dest='rtpextract', action="count")
    parser.add_argument('-r', '-rtp_port', type=str, help='RTP port to extract streams', dest='rtpport', default="")
    parser.add_argument('-o', '--output_file', type=str, help='Save RTP streams into a PCAP file', dest='ofile', default="")
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    if args.rtpextract and (not args.rtpport or not args.ofile):
        print(
            'error: -rtp_extract requires -r/--rtp_port and -o/--output_file')
        sys.exit()

    if not args.rtpextract and (args.rtpport or args.ofile):
        print(
            'error: -rtp_extract requires -r/--rtp_port and -o/--output_file')
        sys.exit()

    if len(sys.argv) < 4:
        print(
            'error: you must write a filter (with -filter). Use -h to show help')
        sys.exit()

    try:
        FILE = args.file
        FILTER = args.filter
        RTPPORT = args.rtpport
        OFILE = args.ofile
        NOCOLOR = args.nocolor

        return FILE, FILTER, RTPPORT, OFILE, NOCOLOR
    except ValueError:
        print('[-] Error')
        sys.exit(1)


def get_spoof_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████
██▀▄─██▄─▄▄▀█▄─▄▄─███─▄▄▄▄█▄─▄▄─█─▄▄─█─▄▄─█▄─▄▄─█
██─▀─███─▄─▄██─▄▄▄███▄▄▄▄─██─▄▄▄█─██─█─██─██─▄███
▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▄▄▀▄▄▄▀▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= ARP Spoofing attack =-''' + WHITE,
        epilog=BWHITE + '''
ARP spoofing is a type of attack in which a malicious actor sends falsified ARP (Address Resolution Protocol) 
messages over a local area network. This results in the linking of an attacker's MAC address with the IP address 
of a legitimate computer or server on the network.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address (ex: 192.168.0.10 | 192.168.0.0/24 | 192.168.0.1,192.168.0.2)', dest="ipaddr")
    parser.add_argument('-gw', help='Set Gateway (by default try to get it)', dest='gw', default="")
    parser.add_argument('-f', '--file', type=str, help='File with several IPs or network ranges', dest='file', default='')
    parser.add_argument('-v', '--verbose', help='Increase verbosity (no data displayed by default)', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.ipaddr and not args.file:
        print(
            'error: one of the following arguments are required: -i/--ip, -f/--file')
        sys.exit()

    IPADDR = args.ipaddr
    GW = args.gw
    FILE = args.file
    VERBOSE = args.verbose

    MORE_VERBOSE = args.more_verbose
    if MORE_VERBOSE == 1:
        VERBOSE = 2

    return IPADDR, VERBOSE, GW, FILE


def get_sniff_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███─▄▄▄▄█▄─▀█▄─▄█▄─▄█▄─▄▄─█▄─▄▄─█
█▄▄▄▄─██─███─▄▄▄███▄▄▄▄─██─█▄▀─███─███─▄████─▄███
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▀▄▄▄▀▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= SIP Network sniffing =-''' + WHITE,
        epilog=BWHITE + '''
Network sniffer for SIP protocol.
 
''')

    # Add arguments
    parser.add_argument('-d', '--dev', help='Set Device (by default try to get it)', dest='dev', default="")
    parser.add_argument('-o', '--output_file', type=str, help='Save output into a PCAP file', dest='ofile', default="")
    parser.add_argument('-p', '--proto', help='Protocol to sniff: udp|tcp|tls|all', dest='proto', default="all")
    parser.add_argument('-auth', help='Show only auth digest', dest='auth', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity (no data displayed by default)', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        DEV = args.dev
        OFILE = args.ofile
        PROTO = args.proto
        AUTH = args.auth
        VERBOSE = args.verbose

        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2

        return DEV, OFILE, AUTH, VERBOSE, PROTO
    except ValueError:
        print('[-] Error')
        sys.exit(1)

def get_sipping_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████▀█
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄─█▄─▄█▄─▀█▄─▄█─▄▄▄▄█
█▄▄▄▄─██─███─▄▄▄████─▄▄▄██─███─█▄▀─██─██▄─█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▀▀▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= SIP Ping =-''' + WHITE,
        epilog=BWHITE + '''
Simple Ping to test if the server/device is available.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-r', '--port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='SIP Method: options|invite|register|subscribe|cancel|bye|...', dest='method', default='options')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-ft', '--from_tag', type=str, help='From Tag', dest='from_tag', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-tt', '--to_tag', type=str, help='To Tag', dest='to_tag', default='')
    parser.add_argument('-user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('-pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-digest', type=str, help='Add a customized Digest header', dest='digest', default='')
    parser.add_argument('-branch', type=str, help='Customize Branch header', dest='branch', default='')
    parser.add_argument('-cid', '--callid', type=str, help='Customize CallID header', dest='callid', default='')
    parser.add_argument('-cseq', type=str, help='Customize Seq number', dest='cseq', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-local-ip', type=str, help='Set local IP address (by default try to get it)', dest='localip', default='')
    parser.add_argument('-n', '--number', type=int, help='Number of requests (default: non stop)', dest='number', default=0)
    parser.add_argument('-in', '--interval', type=int, help='Wait interval seconds between sending each packet (default: 1 sec)', dest='interval', default=1)
    parser.add_argument('-ppi', type=str, help='P-Preferred-Identity', dest='ppi', default='')
    parser.add_argument('-pai', type=str, help='P-Asserted-Identity', dest='pai', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    HOST = args.ipaddr
    PROXY = args.proxy
    RPORT = args.rport
    PROTO = args.proto
    METHOD = args.method
    DOMAIN = args.domain
    CONTACTDOMAIN = args.contact_domain
    FROMNAME = args.from_name
    FROMUSER = args.from_user
    FROMDOMAIN = args.from_domain
    FROMTAG = args.from_tag
    TONAME = args.to_name
    TOUSER = args.to_user
    TOTAG = args.to_tag
    TODOMAIN = args.to_domain
    USER = args.user
    PWD = args.pwd
    DIGEST = args.digest
    BRANCH = args.branch
    CALLID = args.callid
    CSEQ = args.cseq
    UA = args.user_agent
    LOCALIP = args.localip
    NUMBER = args.number
    INTERVAL = args.interval
    PPI = args.ppi
    PAI = args.pai

    return IPADDR, HOST, PROXY, RPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, FROMTAG, TONAME, TOUSER, TODOMAIN, TOTAG, USER, PWD, DIGEST, BRANCH, CALLID, CSEQ, UA, LOCALIP, NUMBER, INTERVAL, PPI, PAI


def get_wssend_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████
█▄─█▀▀▀█─▄█─▄▄▄▄███─▄▄▄▄█▄─▄▄─█▄─▀█▄─▄█▄─▄▄▀█
██─█─█─█─██▄▄▄▄─███▄▄▄▄─██─▄█▀██─█▄▀─███─██─█
▀▀▄▄▄▀▄▄▄▀▀▄▄▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Send a customized message =-''' + WHITE,
        epilog=BWHITE + '''
Send SIP messages over WebSockets.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=str, help='Target port', dest='remote_port', required=True)
    parser.add_argument('-path', type=str, help='WS path (Ex: /ws)', dest='path', default='')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='WSS')
    parser.add_argument('-m', '--method', type=str, help='SIP Method: options|invite|register|subscribe|cancel|bye|...', dest='method', default='OPTIONS')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-ft', '--from_tag', type=str, help='From Tag', dest='from_tag', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-tt', '--to_tag', type=str, help='To Tag', dest='to_tag', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-ppi', type=str, help='P-Preferred-Identity', dest='ppi', default='')
    parser.add_argument('-pai', type=str, help='P-Asserted-Identity', dest='pai', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    PORT = args.remote_port
    PATH = args.path
    VERBOSE = args.verbose
    PROTO = args.proto
    METHOD = args.method
    DOMAIN = args.domain
    CONTACTDOMAIN = args.contact_domain
    FROMNAME = args.from_name
    FROMUSER = args.from_user
    FROMDOMAIN = args.from_domain
    FROMTAG = args.from_tag
    TONAME = args.to_name
    TOUSER = args.to_user
    TOTAG = args.to_tag
    TODOMAIN = args.to_domain
    UA = args.user_agent
    PPI = args.ppi
    PAI = args.pai

    return IPADDR, PORT, PATH, VERBOSE, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, FROMTAG, TONAME, TOUSER, TOTAG, TODOMAIN, UA, PPI, PAI


def get_sipfuzzer_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  SIPPTS''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

████████████████████████████████████████████████████████
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄─█▄─██─▄█░▄▄░▄█░▄▄░▄█▄─▄▄─█▄─▄▄▀█
█▄▄▄▄─██─███─▄▄▄████─▄████─██─███▀▄█▀██▀▄█▀██─▄█▀██─▄─▄█
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▀▀▀▀▄▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/sippts''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= Perform a SIP method fuzzing attack =-''' + WHITE,
        epilog=BWHITE + '''
SIP Fuzzer uses Radamsa to generate a lot of malformed headers to try the robustness of the server/device.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-proxy', '--outbound_proxy', type=str, help='Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)', dest="proxy", default="")
    parser.add_argument('-a', '--all', help='Fuzz all data (by default fuzz header values)', dest="all", action="count")
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='remote_port', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-d', '--delay', type=float, help='Delay between each message (default: 0)', dest='delay', default=0)
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header for pinging (default: pplsip)', dest='user_agent', default='pplsip')

    # Array for all arguments passed to script
    args = parser.parse_args()

    IPADDR = args.ipaddr
    PROXY = args.proxy
    RPORT = args.remote_port
    PROTO = args.proto
    VERBOSE = args.verbose
    ALL = args.all
    DELAY = args.delay
    UA = args.user_agent

    return IPADDR, PROXY, RPORT, PROTO, VERBOSE, ALL, DELAY, UA
