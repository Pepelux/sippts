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
    print(WHITE)
    screen_clear()

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
    parser.add_argument('-i', '--ip', type=str, help='Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24 | 192.168.0.0-255.255.0.0)', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=str, help='Ports to scan. Ex: 5060 | 5070,5080 | 5060-5080 | 5060,5062,5070-5080 (default: 5060)', dest='remote_port', default='5060')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls|all (default: udp)', dest='proto', default='udp')
    parser.add_argument('-m', '--method', type=str, help='Method used to scan: options, invite, register (default: options)', dest='method', default='options')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 100)', dest='threads', default=100)
    parser.add_argument('-ping', help='Ping host before scan', dest='ping', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")

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
        PORT = args.remote_port
        PROTO = args.proto
        METHOD = args.method
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        TONAME = args.to_name
        TOUSER = args.to_user
        UA = args.user_agent
        THREADS = args.threads
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        PING = args.ping

        return IPADDR, PORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, UA, THREADS, VERBOSE, PING
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipexten_args():
    print(WHITE)
    screen_clear()

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

        return IPADDR, RPORT, EXTEN, PREFIX, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMUSER, UA, THREADS, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipremotecrack_args():
    print(WHITE)
    screen_clear()

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
    parser.add_argument('-pr', '--prefix', type=str, help='Prefix for extensions, used for authentication', dest='prefix', default='')
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-w', '--wordlist', help='Wordlist for bruteforce', dest='wordlist', default="", required=True)
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 10)', dest='threads', default=10)

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
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        UA = args.user_agent
        WORDLIST = args.wordlist
        THREADS = args.threads

        return IPADDR, RPORT, EXTEN, PREFIX, PROTO, DOMAIN, CONTACTDOMAIN, UA, WORDLIST, THREADS
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipdigestleak_args():
    print(WHITE)
    screen_clear()

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
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=False)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 5060)', dest='rport', default=5060)
    parser.add_argument('-p', '--proto', type=str, help='Protocol: udp|tcp (default: udp)', dest='proto', default='udp')
    parser.add_argument('-d', '--domain', type=str, help='SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)', dest='domain', default='')
    parser.add_argument('-cd', '--contact_domain', type=str, help='Domain or IP address for Contact header. Ex: 10.0.1.2', dest='contact_domain', default='')
    parser.add_argument('-fn', '--from_name', type=str, help='From Name. Ex: Bob', dest='from_name', default='')
    parser.add_argument('-fu', '--from_user', type=str, help='From User (default: 100)', dest='from_user', default='100')
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-o', '--output-file', type=str, help='Save digest to file in SipCrack format', dest='ofile', default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.ipaddr and not args.calldb and not args.calldb_local:
        print(
            'error: one of the following arguments are required: -i/--ip, -calldb, -calldblocal')
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
        RPORT = args.rport
        PROTO = args.proto
        DOMAIN = args.domain
        CONTACTDOMAIN = args.contact_domain
        FROMNAME = args.from_name
        FROMUSER = args.from_user
        TONAME = args.to_name
        TOUSER = args.to_user
        UA = args.user_agent
        OFILE = args.ofile

        return IPADDR, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, UA, OFILE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipinvite_args():
    print(WHITE)
    screen_clear()

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
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('-t', '--transfer', type=str, help='Phone number to transfer the call', dest='transfer_number', default='')
    parser.add_argument('--user', type=str, help='Authentication user', dest='user', default='')
    parser.add_argument('--pass', type=str, help='Authentication password', dest='pwd', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")

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
        TONAME = args.to_name
        TOUSER = args.to_user
        TRANSFER = args.transfer_number
        USER = args.user
        PWD = args.pwd
        UA = args.user_agent
        VERBOSE = args.verbose

        return IPADDR, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, TRANSFER, USER, PWD, UA, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipcrack_args():
    print(WHITE)
    screen_clear()

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
    print(WHITE)
    screen_clear()

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
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
    parser.add_argument('--digest', type=str, help='Digest', dest='digest', default='')
    parser.add_argument('-ua', '--user_agent', type=str, help='User-Agent header (default: pplsip)', dest='user_agent', default='pplsip')

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
        TONAME = args.to_name
        TOUSER = args.to_user
        DIGEST = args.digest
        UA = args.user_agent

        return IPADDR, RPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, DIGEST, UA
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipenumerate_args():
    print(WHITE)
    screen_clear()

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
Enumerate available methods of a SIP sevice/server.
 
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

        return IPADDR, RPORT, PROTO, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, UA
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)


def get_sipdump_args():
    print(WHITE)
    screen_clear()

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
    print(WHITE)
    screen_clear()

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
    parser.add_argument('-tn', '--to_name', type=str, help='To Name. Ex: Alice', dest='to_name', default='')
    parser.add_argument('-tu', '--to_user', type=str, help='To User (default: 100)', dest='to_user', default='100')
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
        TONAME = args.to_name
        TOUSER = args.to_user
        DIGEST = args.digest
        UA = args.user_agent
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2

        return IPADDR, RPORT, PROTO, METHOD, DOMAIN, CONTACTDOMAIN, FROMNAME, FROMUSER, TONAME, TOUSER, DIGEST, UA, VERBOSE
    except ValueError:
        print('[-] Error: Bad IP format')
        sys.exit(1)
