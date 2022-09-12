import sys
import argparse
import socket
from IPy import IP
from lib.functions import screen_clear

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


def get_sipscan_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ░██████╗░█████╗░░█████╗░███╗░░██╗
██╔════╝██║██╔══██╗  ██╔════╝██╔══██╗██╔══██╗████╗░██║
╚█████╗░██║██████╔╝  ╚█████╗░██║░░╚═╝███████║██╔██╗██║
░╚═══██╗██║██╔═══╝░  ░╚═══██╗██║░░██╗██╔══██║██║╚████║
██████╔╝██║██║░░░░░  ██████╔╝╚█████╔╝██║░░██║██║░╚███║
╚═════╝░╚═╝╚═╝░░░░░  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BBLUE + ''' -= SIP scanner =-''' + WHITE,
        epilog=BWHITE + '''
Fast SIP scanner using multithread. Sipscan can check several IPs and port ranges. It works with 
UDP, TCP and TLS protocols.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24 | 192.168.0.0-255.255.0.0)', dest="ipaddr")
    parser.add_argument('-r', '--remote_port', type=str, help='Ports to scan. Ex: 5060 | 5070,5080 | 5060-5080 | 5060,5062,5070-5080 (default: 5060)', dest='remote_port', default='5060')
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
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 100)', dest='threads', default=100)
    parser.add_argument('-ping', help='Ping host before scan', dest='ping', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-f', '--file', type=str, help='File with several IPs or network ranges', dest='file', default='')
    parser.add_argument('--nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.ipaddr and not args.file:
        print(
            'error: one of the following arguments are required: -i/--ip, -f/--file')
        sys.exit()

    try:
        if args.ipaddr:
            try:
                ip = socket.gethostbyname(args.ipaddr)
                IPADDR = IP(ip)
            except:
                IPADDR = IP(args.ipaddr)
        else:
            IPADDR = ''
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

        return IPADDR, PORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, UA, THREADS, VERBOSE, PING, FILE, NOCOLOR
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipexten_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ███████╗██╗░░██╗████████╗███████╗███╗░░██╗
██╔════╝██║██╔══██╗  ██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝████╗░██║
╚█████╗░██║██████╔╝  █████╗░░░╚███╔╝░░░░██║░░░█████╗░░██╔██╗██║
░╚═══██╗██║██╔═══╝░  ██╔══╝░░░██╔██╗░░░░██║░░░██╔══╝░░██║╚████║
██████╔╝██║██║░░░░░  ███████╗██╔╝╚██╗░░░██║░░░███████╗██║░╚███║
╚═════╝░╚═╝╚═╝░░░░░  ╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚══╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= Identify extensions on a PBX =-''' + WHITE,
        epilog=BWHITE + '''
Identifies extensions on a SIP server. Also tells you if the extension line requires authentication 
or not. Sipexten uses multithread and can check several IPs and port ranges.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='remote_port', default=5060)
    parser.add_argument('-e', '--exten', type=str, help='Extensions to scan. Ex: 100 | 100,102,105 | 100-200 | 100,102,200-300 (default: 100-300)', dest='exten', default='100-300')
    parser.add_argument('-pr', '--prefix', type=str, help='Prefix for extensions, used for authentication', dest='prefix', default='')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='Method used to scan: options, invite, register (default: register)', dest='method', default='register')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 100)', dest='threads', default=100)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('--nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        try:
            ip = socket.gethostbyname(args.ipaddr)
            IPADDR = IP(ip)
        except:
            IPADDR = IP(args.ipaddr)
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

        return IPADDR, RPORT, EXTEN, PREFIX, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMUSER, UA, THREADS, VERBOSE, NOCOLOR
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipremotecrack_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ██████╗░███████╗███╗░░░███╗░█████╗░████████╗███████╗  ░█████╗░██████╗░░█████╗░░█████╗░██╗░░██╗
██╔════╝██║██╔══██╗  ██╔══██╗██╔════╝████╗░████║██╔══██╗╚══██╔══╝██╔════╝  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
╚█████╗░██║██████╔╝  ██████╔╝█████╗░░██╔████╔██║██║░░██║░░░██║░░░█████╗░░  ██║░░╚═╝██████╔╝███████║██║░░╚═╝█████═╝░
░╚═══██╗██║██╔═══╝░  ██╔══██╗██╔══╝░░██║╚██╔╝██║██║░░██║░░░██║░░░██╔══╝░░  ██║░░██╗██╔══██╗██╔══██║██║░░██╗██╔═██╗░
██████╔╝██║██║░░░░░  ██║░░██║███████╗██║░╚═╝░██║╚█████╔╝░░░██║░░░███████╗  ╚█████╔╝██║░░██║██║░░██║╚█████╔╝██║░╚██╗
╚═════╝░╚═╝╚═╝░░░░░  ╚═╝░░╚═╝╚══════╝╚═╝░░░░░╚═╝░╚════╝░░░░╚═╝░░░╚══════╝  ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= Remote password cracker =-''' + WHITE,
        epilog=BWHITE + '''
A password cracker making use of digest authentication. Sipcrack uses multithread and can test 
passwords for several users using bruteforce.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='remote_port', default=5060)
    parser.add_argument('-e', '--exten', type=str, help='Extensions to attack. Ex: 100 | 100,102,105 | 100-200 | 100,102,200-300', dest='exten', required=True)
    parser.add_argument('-au', '--auth-user', type=str, help='Use a custom SIP Auth User instead the extension', dest='authuser', default="")
    parser.add_argument('-pr', '--prefix', type=str, help='Prefix for auth user, used for authentication', dest='prefix', default='')
    parser.add_argument('-l', '--lenght', type=str, help='Lenght of the extensions (if sett, left padding with 0\'s', dest='lenght', default='')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-w', '--wordlist', help='Wordlist for bruteforce', dest='wordlist', default="", required=True)
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 10)', dest='threads', default=10)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('--nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        try:
            ip = socket.gethostbyname(args.ipaddr)
            IPADDR = IP(ip)
        except:
            IPADDR = IP(args.ipaddr)
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

        return IPADDR, RPORT, EXTEN, PREFIX, AUTHUSER, LENGHT, PROTO, DOMAIN, CONTACTDOMAIN, UA, WORDLIST, THREADS, VERBOSE, NOCOLOR
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipdigestleak_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ██████╗░██╗░██████╗░███████╗░██████╗████████╗  ██╗░░░░░███████╗░█████╗░██╗░░██╗
██╔════╝██║██╔══██╗  ██╔══██╗██║██╔════╝░██╔════╝██╔════╝╚══██╔══╝  ██║░░░░░██╔════╝██╔══██╗██║░██╔╝
╚█████╗░██║██████╔╝  ██║░░██║██║██║░░██╗░█████╗░░╚█████╗░░░░██║░░░  ██║░░░░░█████╗░░███████║█████═╝░
░╚═══██╗██║██╔═══╝░  ██║░░██║██║██║░░╚██╗██╔══╝░░░╚═══██╗░░░██║░░░  ██║░░░░░██╔══╝░░██╔══██║██╔═██╗░
██████╔╝██║██║░░░░░  ██████╔╝██║╚██████╔╝███████╗██████╔╝░░░██║░░░  ███████╗███████╗██║░░██║██║░╚██╗
╚═════╝░╚═╝╚═╝░░░░░  ╚═════╝░╚═╝░╚═════╝░╚══════╝╚═════╝░░░░╚═╝░░░  ╚══════╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= Exploit the SIP Digest Leak vulnerability =-''' + WHITE,
        epilog=BWHITE + '''
The SIP Digest Leak is a vulnerability that affects a large number of SIP Phones, including both hardware 
and software IP Phones as well as phone adapters (VoIP to analogue). The vulnerability allows leakage of 
the Digest authentication response, which is computed from the password. An offline password attack is then 
possible and can recover most passwords based on the challenge response.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
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
    parser.add_argument('-o', '--output-file', type=str, help='Save digest to file in SipCrack format', dest='ofile', default='')
    parser.add_argument('--user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('--pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        if args.ipaddr:
            try:
                ip = socket.gethostbyname(args.ipaddr)
                IPADDR = IP(ip)
            except:
                IPADDR = IP(args.ipaddr)
        else:
            IPADDR = ''
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
        USER = args.user
        PWD = args.pwd
        VERBOSE = args.verbose

        return IPADDR, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, UA, OFILE, USER, PWD, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipinvite_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ██╗███╗░░██╗██╗░░░██╗██╗████████╗███████╗
██╔════╝██║██╔══██╗  ██║████╗░██║██║░░░██║██║╚══██╔══╝██╔════╝
╚█████╗░██║██████╔╝  ██║██╔██╗██║╚██╗░██╔╝██║░░░██║░░░█████╗░░
░╚═══██╗██║██╔═══╝░  ██║██║╚████║░╚████╔╝░██║░░░██║░░░██╔══╝░░
██████╔╝██║██║░░░░░  ██║██║░╚███║░░╚██╔╝░░██║░░░██║░░░███████╗
╚═════╝░╚═╝╚═╝░░░░░  ╚═╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝░░░╚═╝░░░╚══════╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= SIP Invite attack =-''' + WHITE,
        epilog=BWHITE + '''
Checks if a server allow us to make calls without authentication. If the SIP server has a bad 
configuration, it will allow us to make calls to external numbers. Also it can allow us to transfer 
the call to a second external number.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('-t', '--transfer', type=str, help='Phone number to transfer the call', dest='transfer_number', default='')
    parser.add_argument('--user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('--pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('--no-sdp', help='Do not send SDP (by default is included)', dest='nosdp', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('--sdes', help='Use SDES in SDP protocol', dest='sdes', action="count")
    parser.add_argument('--nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        try:
            ip = socket.gethostbyname(args.ipaddr)
            IPADDR = IP(ip)
        except:
            IPADDR = IP(args.ipaddr)
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
        TRANSFER = args.transfer_number
        USER = args.user
        PWD = args.pwd
        UA = args.user_agent
        NOSDP = args.nosdp
        VERBOSE = args.verbose
        SDES = args.sdes
        NOCOLOR = args.nocolor

        return IPADDR, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, TRANSFER, USER, PWD, UA, NOSDP, VERBOSE, SDES, NOCOLOR
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipcrack_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''

░██████╗██╗██████╗░  ██████╗░██╗░██████╗░███████╗░██████╗████████╗  ░█████╗░██████╗░░█████╗░░█████╗░██╗░░██╗
██╔════╝██║██╔══██╗  ██╔══██╗██║██╔════╝░██╔════╝██╔════╝╚══██╔══╝  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
╚█████╗░██║██████╔╝  ██║░░██║██║██║░░██╗░█████╗░░╚█████╗░░░░██║░░░  ██║░░╚═╝██████╔╝███████║██║░░╚═╝█████═╝░
░╚═══██╗██║██╔═══╝░  ██║░░██║██║██║░░╚██╗██╔══╝░░░╚═══██╗░░░██║░░░  ██║░░██╗██╔══██╗██╔══██║██║░░██╗██╔═██╗░
██████╔╝██║██║░░░░░  ██████╔╝██║╚██████╔╝███████╗██████╔╝░░░██║░░░  ╚█████╔╝██║░░██║██║░░██║╚█████╔╝██║░╚██╗
╚═════╝░╚═╝╚═╝░░░░░  ╚═════╝░╚═╝░╚═════╝░╚══════╝╚═════╝░░░░╚═╝░░░  ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= SIP digest authentication cracking =-''' + WHITE,
        epilog=WHITE + '''Bruteforce charsets
-------------------
ascii_letters             # The ascii_lowercase and ascii_uppercase constants
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
        description= RED + u'''
░██████╗██╗██████╗░  ░██████╗███████╗███╗░░██╗██████╗░
██╔════╝██║██╔══██╗  ██╔════╝██╔════╝████╗░██║██╔══██╗
╚█████╗░██║██████╔╝  ╚█████╗░█████╗░░██╔██╗██║██║░░██║
░╚═══██╗██║██╔═══╝░  ░╚═══██╗██╔══╝░░██║╚████║██║░░██║
██████╔╝██║██║░░░░░  ██████╔╝███████╗██║░╚███║██████╔╝
╚═════╝░╚═╝╚═╝░░░░░  ╚═════╝░╚══════╝╚═╝░░╚══╝╚═════╝░

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= Send a customized message =-''' + WHITE,
        epilog=BWHITE + '''
SIP Send allow us to send a customized SIP message and analyze the response.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp (default: udp)', dest='proto', default='udp')
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
    parser.add_argument('--user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('--pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('--digest', type=str, help='Add a customized Digest header', dest='digest', default='')
    parser.add_argument('--branch', type=str, help='Customize Branch header', dest='branch', default='')
    parser.add_argument('-cid', '--callid', type=str, help='Customize CallID header', dest='callid', default='')
    parser.add_argument('--cseq', type=str, help='Customize Seq number', dest='cseq', default='')
    parser.add_argument('--sdp', help='Include SDP', dest='sdp', action="count")
    parser.add_argument('--sdes', help='Use SDES in SDP protocol', dest='sdes', action="count")
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('--nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.ipaddr)
        IPADDR = IP(ip)
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
        SDP = args.sdp
        SDES = args.sdes
        UA = args.user_agent
        NOCOLOR = args.nocolor

        return IPADDR, RPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, FROMTAG, TONAME, TOUSER, TODOMAIN, TOTAG, USER, PWD, DIGEST, BRANCH, CALLID, CSEQ, SDP, SDES, UA, NOCOLOR
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipenumerate_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ███████╗███╗░░██╗██╗░░░██╗███╗░░░███╗███████╗██████╗░░█████╗░████████╗███████╗
██╔════╝██║██╔══██╗  ██╔════╝████╗░██║██║░░░██║████╗░████║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
╚█████╗░██║██████╔╝  █████╗░░██╔██╗██║██║░░░██║██╔████╔██║█████╗░░██████╔╝███████║░░░██║░░░█████╗░░
░╚═══██╗██║██╔═══╝░  ██╔══╝░░██║╚████║██║░░░██║██║╚██╔╝██║██╔══╝░░██╔══██╗██╔══██║░░░██║░░░██╔══╝░░
██████╔╝██║██║░░░░░  ███████╗██║░╚███║╚██████╔╝██║░╚═╝░██║███████╗██║░░██║██║░░██║░░░██║░░░███████╗
╚═════╝░╚═╝╚═╝░░░░░  ╚══════╝╚═╝░░╚══╝░╚═════╝░╚═╝░░░░░╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= Enumerate methods =-''' + WHITE,
        epilog=BWHITE + '''
Enumerate available methods of a SIP service/server.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.ipaddr)
        IPADDR = IP(ip)
        RPORT = args.rport
        PROTO = args.proto
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        TONAME = args.to_name
        TOUSER = args.to_user
        UA = args.user_agent
        VERBOSE = args.verbose

        return IPADDR, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, UA, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipdump_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
░██████╗██╗██████╗░  ██████╗░██╗░░░██╗███╗░░░███╗██████╗░
██╔════╝██║██╔══██╗  ██╔══██╗██║░░░██║████╗░████║██╔══██╗
╚█████╗░██║██████╔╝  ██║░░██║██║░░░██║██╔████╔██║██████╔╝
░╚═══██╗██║██╔═══╝░  ██║░░██║██║░░░██║██║╚██╔╝██║██╔═══╝░
██████╔╝██║██║░░░░░  ██████╔╝╚██████╔╝██║░╚═╝░██║██║░░░░░
╚═════╝░╚═╝╚═╝░░░░░  ╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝╚═╝░░░░░

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= SIP Dump =-''' + WHITE,
        epilog=BWHITE + '''
Extracts SIP Digest authentications from a PCAP file
 
''')

    # Add arguments
    parser.add_argument('-f', '--file', type=str, help='PCAP file to analyze', dest="file", required=True, default='')
    parser.add_argument('-o', '--output-file', type=str, help='Save digest to file in SipCrack format', dest='ofile', required=True, default='')
 
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
        description= RED + u'''
░██████╗██╗██████╗░  ███████╗██╗░░░░░░█████╗░░█████╗░██████╗░
██╔════╝██║██╔══██╗  ██╔════╝██║░░░░░██╔══██╗██╔══██╗██╔══██╗
╚█████╗░██║██████╔╝  █████╗░░██║░░░░░██║░░██║██║░░██║██║░░██║
░╚═══██╗██║██╔═══╝░  ██╔══╝░░██║░░░░░██║░░██║██║░░██║██║░░██║
██████╔╝██║██║░░░░░  ██║░░░░░███████╗╚█████╔╝╚█████╔╝██████╔╝
╚═════╝░╚═╝╚═╝░░░░░  ╚═╝░░░░░╚══════╝░╚════╝░░╚════╝░╚═════╝░

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= Flood a SIP method =-''' + WHITE,
        epilog=BWHITE + '''
SIP Flood send messages with a selected method
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='SIP Method: options|invite|register|subscribe|cancel|bye|...', dest='method', required=True)
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-fd', '--from_domain', type=str, help='From Domain. Ex: 10.0.0.1', dest='from_domain', default='')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-td', '--to_domain', type=str, help='To Domain. Ex: 10.0.0.1', dest='to_domain', default='')
    parser.add_argument('--digest', type=str, help='Digest', dest='digest', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.ipaddr)
        IPADDR = IP(ip)
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
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2

        return IPADDR, RPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, FROMDOMAIN, TONAME, TOUSER, TODOMAIN, DIGEST, UA, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_rtpbleed_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
██████╗░████████╗██████╗░  ██████╗░██╗░░░░░███████╗███████╗██████╗░
██╔══██╗╚══██╔══╝██╔══██╗  ██╔══██╗██║░░░░░██╔════╝██╔════╝██╔══██╗
██████╔╝░░░██║░░░██████╔╝  ██████╦╝██║░░░░░█████╗░░█████╗░░██║░░██║
██╔══██╗░░░██║░░░██╔═══╝░  ██╔══██╗██║░░░░░██╔══╝░░██╔══╝░░██║░░██║
██║░░██║░░░██║░░░██║░░░░░  ██████╦╝███████╗███████╗███████╗██████╔╝
╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░  ╚═════╝░╚══════╝╚══════╝╚══════╝╚═════╝░

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

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

    try:
        try:
            ip = socket.gethostbyname(args.ipaddr)
            IPADDR = IP(ip)
        except:
            IPADDR = IP(args.ipaddr)
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
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_rtcpbleed_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
██████╗░████████╗░█████╗░██████╗░  ██████╗░██╗░░░░░███████╗███████╗██████╗░
██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗  ██╔══██╗██║░░░░░██╔════╝██╔════╝██╔══██╗
██████╔╝░░░██║░░░██║░░╚═╝██████╔╝  ██████╦╝██║░░░░░█████╗░░█████╗░░██║░░██║
██╔══██╗░░░██║░░░██║░░██╗██╔═══╝░  ██╔══██╗██║░░░░░██╔══╝░░██╔══╝░░██║░░██║
██║░░██║░░░██║░░░╚█████╔╝██║░░░░░  ██████╦╝███████╗███████╗███████╗██████╔╝
╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░░░░  ╚═════╝░╚══════╝╚══════╝╚══════╝╚═════╝░

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

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

    try:
        try:
            ip = socket.gethostbyname(args.ipaddr)
            IPADDR = IP(ip)
        except:
            IPADDR = IP(args.ipaddr)
        SP = args.start_port
        EP = args.end_port
        # Always start on odd port
        if SP % 2 == 0:
            SP = SP + 1
        if EP % 2 == 0:
            EP = EP + 1
        DELAY = args.delay
        return IPADDR, SP, EP, DELAY
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_rtcbleed_flood_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
██████╗░████████╗██████╗░  ██████╗░██╗░░░░░███████╗███████╗██████╗░  ███████╗██╗░░░░░░█████╗░░█████╗░██████╗░
██╔══██╗╚══██╔══╝██╔══██╗  ██╔══██╗██║░░░░░██╔════╝██╔════╝██╔══██╗  ██╔════╝██║░░░░░██╔══██╗██╔══██╗██╔══██╗
██████╔╝░░░██║░░░██████╔╝  ██████╦╝██║░░░░░█████╗░░█████╗░░██║░░██║  █████╗░░██║░░░░░██║░░██║██║░░██║██║░░██║
██╔══██╗░░░██║░░░██╔═══╝░  ██╔══██╗██║░░░░░██╔══╝░░██╔══╝░░██║░░██║  ██╔══╝░░██║░░░░░██║░░██║██║░░██║██║░░██║
██║░░██║░░░██║░░░██║░░░░░  ██████╦╝███████╗███████╗███████╗██████╔╝  ██║░░░░░███████╗╚█████╔╝╚█████╔╝██████╔╝
╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░░░░  ╚═════╝░╚══════╝╚══════╝╚══════╝╚═════╝░  ╚═╝░░░░░╚══════╝░╚════╝░░╚════╝░╚═════╝░

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

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
    parser.add_argument('-p', '--port', type=int, help='Port number to flood', dest='port', required=True)

    # Array for all arguments passed to script
    args = parser.parse_args()
    try:
        try:
            ip = socket.gethostbyname(args.ipaddr)
            IPADDR = IP(ip)
        except:
            IPADDR = IP(args.ipaddr)
        P = args.port
        return IPADDR, P
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_tshark_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''
████████╗░██████╗██╗░░██╗░█████╗░██████╗░██╗░░██╗
╚══██╔══╝██╔════╝██║░░██║██╔══██╗██╔══██╗██║░██╔╝
░░░██║░░░╚█████╗░███████║███████║██████╔╝█████═╝░
░░░██║░░░░╚═══██╗██╔══██║██╔══██║██╔══██╗██╔═██╗░
░░░██║░░░██████╔╝██║░░██║██║░░██║██║░░██║██║░╚██╗
░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝

''' + BWHITE + '''   ''' + GREEN + ''' █▀█ █▀▀ █▀█ █▀▀ █░░ █░█ ▀▄▀''' + BWHITE + '''
''' + BWHITE + '''BY ''' + GREEN + ''' █▀▀ ██▄ █▀▀ ██▄ █▄▄ █▄█ █░█''' + BWHITE + '''

''' + BLUE + ''' -= TShark filters =-''' + WHITE,
        epilog=WHITE + '''
Filters:
-------
stats               SIP packet statistics
dialogs             Show all SIP dialogs
auth                Show auth digest
messages            Show all SIP messages
method <method>     Filter frames by method: register, invite, ...
callids             Show all call-ID
callid <cid>        Filter by call-ID
frame <id>          Show a SIP message filtering by frame number
rtp                 Show all RTP streams
''' + WHITE + '''
\nPCAP manipulation with TShark.
 
''')

    # Add arguments
    parser.add_argument('-f', '--file', type=str, help='PCAP file to analyze', required=True, dest='file', default="")
    parser.add_argument('-filter', help='Filter data to show', dest='filter', default="")
    parser.add_argument('-rtp_extract', help='Extract RTP streams. Ex: --rtp_extract -p 1210 -o rtp.pcap', dest='rtpextract', action="count")
    parser.add_argument('-rport', type=str, help='RTP port to extract streams', dest='rtpport', default="")
    parser.add_argument('-o', '--output-file', type=str, help='Save RTP streams into a PCAP file', dest='ofile', default="")
    parser.add_argument('--nocolor', help='Show result without colors', dest='nocolor', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    if args.rtpextract and (not args.rtpport or not args.ofile):
        print(
            'error: --rtp_extract requires -p/--rtp_port and -o/--output_file')
        sys.exit()

    if not args.rtpextract and (args.rtpport or args.ofile):
        print(
            'error: --rtp_extract requires -p/--rtp_port and -o/--output_file')
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

