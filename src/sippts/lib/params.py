import argparse
import os
import random
import sys
import subprocess
import requests
from sippts.lib.functions import load_cve_version
from sippts.lib.logos import Logo

BRED = "\033[1;31;20m"
RED = "\033[0;31;20m"
BRED_BLACK = "\033[1;30;41m"
RED_BLACK = "\033[0;30;41m"
BGREEN = "\033[1;32;20m"
GREEN = "\033[0;32;20m"
BGREEN_BLACK = "\033[1;30;42m"
GREEN_BLACK = "\033[0;30;42m"
BYELLOW = "\033[1;33;20m"
YELLOW = "\033[0;33;20m"
BBLUE = "\033[1;34;20m"
BLUE = "\033[0;34;20m"
BMAGENTA = "\033[1;35;20m"
MAGENTA = "\033[0;35;20m"
BCYAN = "\033[1;36;20m"
CYAN = "\033[0;36;20m"
BWHITE = "\033[1;37;20m"
WHITE = "\033[0;37;20m"

local_version = "4.0.12"


def get_sippts_args():
    try:
        command = [
            "curl",
            "https://raw.githubusercontent.com/Pepelux/sippts/master/version",
            "-H 'Cache-Control: no-cache, no-store'",
        ]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        output = result.stdout
        error = result.stderr

        if result.returncode == 0:
            current_version = output.replace("\n", "")
        else:
            current_version = local_version
    except:
        current_version = local_version

    if local_version != current_version:
        local_version_status = BRED + """ (last version """ + current_version + """)"""
    else:
        local_version_status = BWHITE + """ (updated)"""

    local_cve_version = load_cve_version()

    try:
        command = [
            "curl",
            "https://raw.githubusercontent.com/Pepelux/sippts/master/cveversion",
            "-H 'Cache-Control: no-cache, no-store'",
        ]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        output = result.stdout
        error = result.stderr

        if result.returncode == 0 and output != "404: Not Found":
            current_cve_version = output.replace("\n", "")
        else:
            current_cve_version = local_cve_version
    except:
        current_cve_version = local_cve_version

    if local_cve_version != current_cve_version:
        local_cve_version_status = (
            BRED + """ (last version """ + current_cve_version + """)"""
        )
    else:
        local_cve_version_status = BWHITE + """ (updated)"""

    rnd = random.randint(1, 4)
    if rnd == 1:
        color = RED
    elif rnd == 2:
        color = GREEN
    elif rnd == 3:
        color = CYAN
    else:
        color = YELLOW

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50
        ),
        description=color
        + Logo("sippts").get_logo(
            color,
            local_version,
            local_version_status,
            local_cve_version,
            local_cve_version_status,
        )
        + """

"""
        + BWHITE
        + """ -= """
        + BGREEN
        + """SIPPTS"""
        + BWHITE
        + """ is a set of tools for auditing VoIP systems based on the SIP protocol =- """
        + WHITE,
        epilog=WHITE
        + """Command help:
  sippts <command> -h

""",
    )

    ##################
    # General params #
    ##################
    parser._positionals.title = "Commands"
    parser._optionals.title = "Options"
    subparsers = parser.add_subparsers(dest="command")
    parser.add_argument("-up", help="Update scripts", dest="update", action="count")

    ##########
    # videos #
    ##########
    parser_video = subparsers.add_parser(
        "video",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Animated help",
        add_help=False,
    )

    mode = parser_video.add_argument_group("Video")
    mode.add_argument(
        "-b", help="Scanning, enumeration and cracking", dest="basic", action="count"
    )
    mode.add_argument(
        "-d",
        help="Extracting and cracking users of a PCAP file",
        dest="digest",
        action="count",
    )
    mode.add_argument(
        "-l", help="SIP Digest Leak vulnerability attack", dest="leak", action="count"
    )
    mode.add_argument(
        "-s", help="Spoofing and sniffing data", dest="spoof", action="count"
    )

    other = parser_video.add_argument_group("Other options")
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ################
    # scan command #
    ################
    parser_scan = subparsers.add_parser(
        "scan",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Fast SIP scanner",
        add_help=False,
        description=RED
        + Logo("sipscan").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """scan"""
        + YELLOW
        + """ is a fast SIP scanner using multithread that can check several IPs and port ranges. It works with UDP, TCP and TLS protocols."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Searching for SIP services and devices with default ports (5060/udp) on the local network
"""
        + WHITE
        + """     sippts scan -i 192.168.0.0/24
"""
        + YELLOW
        + """  Extend the port range from 5060 to 5080 and look for UDP, TCP and TLS services
"""
        + WHITE
        + """     sippts scan -i 192.168.0.0/24 -r 5060-5080 -p all
"""
        + YELLOW
        + """  Load several target IP addresses from a file
"""
        + WHITE
        + """     sippts scan -f targets.txt
"""
        + YELLOW
        + """  Random scanning for non-sequential scanning of IP ranges
"""
        + WHITE
        + """     sippts scan -f targets.txt -random
"""
        + YELLOW
        + """  Establishing an unidentified user agent as an attack tool
"""
        + WHITE
        + """     sippts scan -ua Grandstream
"""
        + YELLOW
        + """  Scan all ports and protocols of an address range using 500 threads (slow)
"""
        + WHITE
        + """     sippts scan -f targets.txt -r all -p all -th 500 -ua Grandstream
"""
        + YELLOW
        + """  Typical scanning for large ranges
"""
        + WHITE
        + """     sippts scan -f targets.txt -r 5060-5080 -p all -th 500 -ua Grandstream -v -fp -o output.txt
""",
    )

    target = parser_scan.add_argument_group("Target")
    target.add_argument(
        "-i",
        metavar="IP|HOST",
        type=str,
        help="Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24)",
        dest="ipaddr",
    )
    target.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="File with several IPs or network ranges",
        dest="file",
        default="",
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=str,
        help="Ports to scan. Ex: 5060 | 5070,5080 | 5060-5080 | 5060,5062,5070-5080 | ALL for 1-65536 (default: 5060)",
        dest="rport",
        default="5060",
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls|all (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS", "ALL"],
        default="udp",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_scan.add_argument_group("Headers")
    headers.add_argument(
        "-m",
        metavar="METHOD",
        type=str.upper,
        help="SIP method: options, invite, register (default: options)",
        dest="method",
        choices=["OPTIONS", "REGISTER", "INVITE"],
        default="options",
    )
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-ppi",
        metavar="PPI",
        type=str,
        help="P-Preferred-Identity",
        dest="ppi",
        default="",
    )
    headers.add_argument(
        "-pai",
        metavar="PAI",
        type=str,
        help="P-Asserted-Identity",
        dest="pai",
        default="",
    )

    log = parser_scan.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-vv", help="Increase more verbosity", dest="more_verbose", action="count"
    )
    log.add_argument(
        "-nocolor", help="Show result without colors", dest="nocolor", action="count"
    )
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save data into a log file",
        dest="ofile",
        default="",
    )
    log.add_argument(
        "-oi",
        metavar="FILE",
        type=str,
        help="Save IPs into a log file",
        dest="oifile",
        default="",
    )
    log.add_argument("-cve", help="Show possible CVEs", dest="cve", action="count")

    other = parser_scan.add_argument_group("Other options")
    other.add_argument(
        "-th",
        metavar="THREADS",
        type=int,
        help="Number of threads (default: 200)",
        dest="threads",
        default=200,
    )
    other.add_argument(
        "-t",
        metavar="TIMEOUT",
        type=int,
        help="Sockets timeout (default: 5)",
        dest="timeout",
        default=5,
    )
    other.add_argument(
        "-ping", help="Ping host before scan", dest="ping", action="count"
    )
    other.add_argument("-fp", help="Try to fingerprinting", dest="fp", action="count")
    other.add_argument(
        "-random", help="Randomize target hosts", dest="random", action="count"
    )
    other.add_argument(
        "-local-ip",
        metavar="IP",
        type=str,
        help="Set local IP address (by default try to get it)",
        dest="localip",
        default="",
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #################
    # exten command #
    #################
    parser_exten = subparsers.add_parser(
        "exten",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Search SIP extensions of a PBX",
        add_help=False,
        description=RED
        + Logo("sipexten").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """exten"""
        + YELLOW
        + """ identifies extensions on a SIP server. Also tells you if the extension line requires authentication."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Searching for SIP extensions between 100 and 200
"""
        + WHITE
        + """     sippts exten -i 192.168.0.1 -e 100-200
"""
        + YELLOW
        + """  Searching for SIP extensions between 100 and 200 using TLS
"""
        + WHITE
        + """     sippts exten -i 192.168.0.1 -e 100-200 -p tls
"""
        + YELLOW
        + """  Use prefix for auth user (ex: company100 to company200)
"""
        + WHITE
        + """     sippts exten -i 192.168.0.1 -pr company -e 100-200 -p tls
""",
    )

    target = parser_exten.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-e",
        metavar="EXTEN",
        type=str,
        help="Extensions to scan. Ex: 100 | 100,102,105 | 100-200 | 100,102,200-300 (default: 100-300)",
        dest="exten",
        default="100-300",
    )
    target.add_argument(
        "-pr",
        metavar="PREFIX",
        type=str,
        help="Prefix for extensions, used for authentication",
        dest="prefix",
        default="",
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_exten.add_argument_group("Headers")
    headers.add_argument(
        "-m",
        metavar="METHOD",
        type=str.upper,
        help="SIP method: options, invite, register (default: register)",
        dest="method",
        choices=["OPTIONS", "REGISTER", "INVITE"],
        default="register",
    )
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )

    log = parser_exten.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-vv", help="Increase more verbosity", dest="more_verbose", action="count"
    )
    log.add_argument(
        "-rc",
        metavar="RESPONSE_CODE",
        help="Filter response code (ex: 200)",
        dest="filter",
        default="",
    )
    log.add_argument(
        "-nocolor", help="Show result without colors", dest="nocolor", action="count"
    )
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save data into a log file",
        dest="ofile",
        default="",
    )

    other = parser_exten.add_argument_group("Other options")
    other.add_argument(
        "-th",
        metavar="THREADS",
        type=int,
        help="Number of threads (default: 200)",
        dest="threads",
        default=200,
    )
    other.add_argument(
        "-t",
        metavar="TIMEOUT",
        type=int,
        help="Sockets timeout (default: 5)",
        dest="timeout",
        default=5,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ##################
    # rcrack command #
    ##################
    parser_rcrack = subparsers.add_parser(
        "rcrack",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Remote password cracker",
        add_help=False,
        description=RED
        + Logo("siprcrack").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """rcrack"""
        + YELLOW
        + """ is a remote password cracker making use of digest authentication."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Cracking a single extension
"""
        + WHITE
        + """     sippts rcrack -i 192.168.0.1 -e 100 -w rockrou.txt
"""
        + YELLOW
        + """  Cracking several extensions
"""
        + WHITE
        + """     sippts rcrack -i 192.168.0.1 -e 100-200 -w rockrou.txt
""",
    )

    target = parser_rcrack.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-e",
        metavar="EXTEN",
        type=str,
        help="Extensions or users to attack. Ex: 100 | 100,102,105 | 100-200 | user100",
        dest="exten",
    )
    target.add_argument(
        "-au",
        metavar="AUTH_USER",
        type=str,
        help="Use a custom SIP Auth User instead the extension",
        dest="authuser",
        default="",
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    wordlist = parser_rcrack.add_argument_group("Words")
    wordlist.add_argument(
        "-pr",
        metavar="PREFIX",
        type=str,
        help="Prefix for extensions, used for authentication",
        dest="prefix",
        default="",
    )
    wordlist.add_argument(
        "-l",
        metavar="LENGHT",
        type=str,
        help="Lenght of the extensions (if set, left padding with 0's)",
        dest="lenght",
        default="",
    )
    wordlist.add_argument(
        "-w",
        metavar="WORDLIST",
        help="Wordlist for bruteforce",
        dest="wordlist",
        default="",
    )

    headers = parser_rcrack.add_argument_group("Headers")
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )

    log = parser_rcrack.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-nocolor", help="Show result without colors", dest="nocolor", action="count"
    )

    other = parser_rcrack.add_argument_group("Other options")
    other.add_argument(
        "-th",
        metavar="THREADS",
        type=int,
        help="Number of threads (default: 200)",
        dest="threads",
        default=200,
    )
    other.add_argument(
        "-t",
        metavar="TIMEOUT",
        type=int,
        help="Sockets timeout (default: 5)",
        dest="timeout",
        default=5,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ################
    # send command #
    ################
    parser_send = subparsers.add_parser(
        "send",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Send a customized message",
        add_help=False,
        description=RED
        + Logo("sipsend").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """send"""
        + YELLOW
        + """ allow us to send a customized SIP message and analyze the response."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Send customize INVITE message
"""
        + WHITE
        + """     sippts send -i 192.168.0.1 -m invite -fn Bob -fu 100 -tu Alice
"""
        + YELLOW
        + """  Register a known user
"""
        + WHITE
        + """     sippts send -i 192.168.0.1 -m register -user bob -pass supersecret
""",
    )

    target = parser_send.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-template",
        metavar="FILE",
        type=str,
        help="Template with SIP message",
        dest="template",
        default="",
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-l",
        metavar="LOCAL_PORT",
        type=int,
        help="Local port (default: first free)",
        dest="lport",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_send.add_argument_group("Headers")
    headers.add_argument(
        "-m",
        metavar="METHOD",
        type=str,
        help="SIP method: options, invite, register, bye, ... (default: options)",
        dest="method",
        default="options",
    )
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-ft",
        metavar="FROM_TAG",
        type=str,
        help="From Tag",
        dest="from_tag",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-tt", metavar="TO_TAG", type=str, help="To Tag", dest="to_tag", default=""
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-ppi",
        metavar="PPI",
        type=str,
        help="P-Preferred-Identity",
        dest="ppi",
        default="",
    )
    headers.add_argument(
        "-pai",
        metavar="PAI",
        type=str,
        help="P-Asserted-Identity",
        dest="pai",
        default="",
    )
    headers.add_argument(
        "-header",
        metavar="HEADER",
        type=str,
        help='Add custom header (ex: "Allow-Events: presence"). Multiple headers: hdr1&hdr2 ',
        dest="header",
        default="",
    )
    headers.add_argument(
        "-nc", help="Don't send Contact header", dest="nocontact", action="count"
    )
    headers.add_argument(
        "-branch",
        metavar="BRANCH",
        type=str,
        help="Customize Branch header",
        dest="branch",
        default="",
    )
    headers.add_argument(
        "-cid",
        metavar="CALLID",
        type=str,
        help="Customize CallID header",
        dest="callid",
        default="",
    )
    headers.add_argument(
        "-cseq", metavar="SEQ", help="Customize Seq number", dest="cseq", default=""
    )
    headers.add_argument(
        "-sdp", help="Send SDP in INVITE messages", dest="sdp", action="count"
    )
    headers.add_argument("-sdes", help="Send SDES in SDP", dest="sdes", action="count")
    headers.add_argument(
        "-digest",
        metavar="DIGEST",
        type=str,
        help="Add a customized Digest header",
        dest="digest",
        default="",
    )

    auth = parser_send.add_argument_group("Auth")
    auth.add_argument(
        "-user",
        metavar="AUTH_USER",
        type=str,
        help="Authentication user",
        dest="user",
        default="",
    )
    auth.add_argument(
        "-pass",
        metavar="AUTH_PASS",
        type=str,
        help="Authentication password",
        dest="pwd",
        default="",
    )

    log = parser_send.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-nocolor", help="Show result without colors", dest="nocolor", action="count"
    )
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save data into a log file",
        dest="ofile",
        default="",
    )

    other = parser_send.add_argument_group("Other options")
    other.add_argument(
        "-t",
        metavar="TIMEOUT",
        type=int,
        help="Sockets timeout (default: 5)",
        dest="timeout",
        default=5,
    )
    other.add_argument(
        "-local-ip",
        metavar="IP",
        type=str,
        help="Set local IP address (by default try to get it)",
        dest="localip",
        default="",
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ##################
    # wssend command #
    ##################
    parser_wssend = subparsers.add_parser(
        "wssend",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Send a customized message over WS",
        add_help=False,
        description=RED
        + Logo("wssend").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """wssend"""
        + YELLOW
        + """ allow us to send a customized SIP message over WebSockets and analyze the response."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Send customize INVITE message
"""
        + WHITE
        + """     sippts send -i 192.168.0.1 -m invite -fn Bob -fu 100 -tu Alice
"""
        + YELLOW
        + """  Register a known user
"""
        + WHITE
        + """     sippts send -i 192.168.0.1 -m register -user bob -pass supersecret
""",
    )

    target = parser_wssend.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-path",
        metavar="PATH",
        type=str,
        help="WS path (Ex: /ws)",
        dest="path",
        default="",
    )

    headers = parser_wssend.add_argument_group("Headers")
    headers.add_argument(
        "-m",
        metavar="METHOD",
        type=str.upper,
        help="SIP method: options, invite, register (default: options)",
        dest="method",
        choices=["OPTIONS", "REGISTER", "INVITE"],
        default="options",
    )
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-ft",
        metavar="FROM_TAG",
        type=str,
        help="From Tag",
        dest="from_tag",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-tt", metavar="TO_TAG", type=str, help="To Tag", dest="to_tag", default=""
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-ppi",
        metavar="PPI",
        type=str,
        help="P-Preferred-Identity",
        dest="ppi",
        default="",
    )
    headers.add_argument(
        "-pai",
        metavar="PAI",
        type=str,
        help="P-Asserted-Identity",
        dest="pai",
        default="",
    )

    log = parser_wssend.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")

    other = parser_wssend.add_argument_group("Other options")
    other.add_argument(
        "-local-ip",
        metavar="IP",
        type=str,
        help="Set local IP address (by default try to get it)",
        dest="localip",
        default="",
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #####################
    # enumerate command #
    #####################
    parser_enumerate = subparsers.add_parser(
        "enumerate",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Enumerate methods of a SIP server",
        add_help=False,
        description=RED
        + Logo("sipenumerate").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """enumerate"""
        + YELLOW
        + """ check the available methods of a SIP service/server."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Enumerate methods
"""
        + WHITE
        + """     sippts enumerate -i 192.168.0.1
"""
        + YELLOW
        + """  Custom User-Agent
"""
        + WHITE
        + """     sippts enumerate -i 192.168.0.1 -ua Grandstream
""",
    )

    target = parser_enumerate.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_enumerate.add_argument_group("Headers")
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-ft",
        metavar="FROM_TAG",
        type=str,
        help="From Tag",
        dest="from_tag",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )

    log = parser_enumerate.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")

    other = parser_enumerate.add_argument_group("Other options")
    other.add_argument(
        "-t",
        metavar="TIMEOUT",
        type=int,
        help="Sockets timeout (default: 5)",
        dest="timeout",
        default=5,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #########################
    # sipdigestleak command #
    #########################
    parser_leak = subparsers.add_parser(
        "leak",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Exploit SIP Digest Leak vulnerability",
        add_help=False,
        description=RED
        + Logo("sipdigestleak").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """leak"""
        + YELLOW
        + """ exploits the SIP Digest Leak vulnerability that affects a large number of SIP Phones."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Exploit a single phone
"""
        + WHITE
        + """     sippts leak -i 192.168.0.1
"""
        + YELLOW
        + """  Exploit a single phone in custom port
"""
        + WHITE
        + """     sippts leak -i 192.168.0.1 -r 5080
"""
        + YELLOW
        + """  Exploit several phones
"""
        + WHITE
        + """     sippts leak -f targets.txt
"""
        + YELLOW
        + """  Custom headers
"""
        + WHITE
        + """     sippts leak -i 192.168.0.1 -fn Bob -fu 200
"""
        + YELLOW
        + """  Save results into file (SipCrack format)
"""
        + WHITE
        + """     sippts leak -i 192.168.0.1 -o output.txt
""",
    )

    target = parser_leak.add_argument_group("Target")
    target.add_argument(
        "-i",
        metavar="IP|HOST",
        type=str,
        help="Host/IP address/network (ex: mysipserver.com | 192.168.0.10 | 192.168.0.0/24)",
        dest="ipaddr",
        default="",
    )
    target.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="File with several IPs (format: ip:port/proto ... one per line)",
        dest="file",
        default="",
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp (default: udp)",
        dest="proto",
        choices=["UDP", "TCP"],
        default="udp",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_leak.add_argument_group("Headers")
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-ppi",
        metavar="PPI",
        type=str,
        help="P-Preferred-Identity",
        dest="ppi",
        default="",
    )
    headers.add_argument(
        "-pai",
        metavar="PAI",
        type=str,
        help="P-Asserted-Identity",
        dest="pai",
        default="",
    )
    headers.add_argument(
        "-sdp", help="Send SDP in INVITE messages", dest="sdp", action="count"
    )
    headers.add_argument("-sdes", help="Send SDES in SDP", dest="sdes", action="count")

    auth = parser_leak.add_argument_group("Auth")
    auth.add_argument(
        "-auth",
        metavar="AUTH_MODE",
        type=str,
        help="Authentication mode [www|proxy] (default: www)",
        dest="auth",
        default="www",
    )
    auth.add_argument(
        "-user",
        metavar="AUTH_USER",
        type=str,
        help="Authentication user",
        dest="user",
        default="",
    )
    auth.add_argument(
        "-pass",
        metavar="AUTH_PASS",
        type=str,
        help="Authentication password",
        dest="pwd",
        default="",
    )

    log = parser_leak.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save digest to file in SipCrack format",
        dest="ofile",
        default="",
    )
    log.add_argument(
        "-l",
        metavar="FILE",
        type=str,
        help="Save result into a log file",
        dest="lfile",
        default="",
    )

    other = parser_leak.add_argument_group("Other options")
    other.add_argument(
        "-local-ip",
        metavar="IP",
        type=str,
        help="Set local IP address (by default try to get it)",
        dest="localip",
        default="",
    )
    other.add_argument(
        "-ping", help="Ping host before send attack", dest="ping", action="count"
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ################
    # ping command #
    ################
    parser_ping = subparsers.add_parser(
        "ping",
        formatter_class=argparse.RawTextHelpFormatter,
        help="SIP ping",
        add_help=False,
        description=RED
        + Logo("sipping").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """ping"""
        + YELLOW
        + """ send a Ping to test if the server/device is available."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Pinging server
"""
        + WHITE
        + """     sippts ping -i 192.168.0.1
"""
        + YELLOW
        + """  Custom User-Agent
"""
        + WHITE
        + """     sippts ping -i 192.168.0.1 -ua Grandstream
""",
    )

    target = parser_ping.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_ping.add_argument_group("Headers")
    headers.add_argument(
        "-m",
        metavar="METHOD",
        type=str.upper,
        help="SIP method: options, invite, register (default: options)",
        dest="method",
        choices=["OPTIONS", "INVITE", "REGISTER"],
        default="options",
    )
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-ft",
        metavar="FROM_TAG",
        type=str,
        help="From Tag",
        dest="from_tag",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-tt", metavar="TO_TAG", type=str, help="To Tag", dest="to_tag", default=""
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-ppi",
        metavar="PPI",
        type=str,
        help="P-Preferred-Identity",
        dest="ppi",
        default="",
    )
    headers.add_argument(
        "-pai",
        metavar="PAI",
        type=str,
        help="P-Asserted-Identity",
        dest="pai",
        default="",
    )
    headers.add_argument(
        "-branch",
        metavar="BRANCH",
        type=str,
        help="Customize Branch header",
        dest="branch",
        default="",
    )
    headers.add_argument(
        "-cid",
        metavar="CALLID",
        type=str,
        help="Customize CallID header",
        dest="callid",
        default="",
    )
    headers.add_argument(
        "-cseq", metavar="SEQ", help="Customize Seq number", dest="cseq", default=""
    )
    headers.add_argument(
        "-digest",
        metavar="DIGEST",
        type=str,
        help="Add a customized Digest header",
        dest="digest",
        default="",
    )

    auth = parser_ping.add_argument_group("Auth")
    auth.add_argument(
        "-user",
        metavar="AUTH_USER",
        type=str,
        help="Authentication user",
        dest="user",
        default="",
    )
    auth.add_argument(
        "-pass",
        metavar="AUTH_PASS",
        type=str,
        help="Authentication password",
        dest="pwd",
        default="",
    )

    other = parser_ping.add_argument_group("Other options")
    other.add_argument(
        "-t",
        metavar="TIMEOUT",
        type=int,
        help="Sockets timeout (default: 5)",
        dest="timeout",
        default=5,
    )
    other.add_argument(
        "-local-ip",
        metavar="IP",
        type=str,
        help="Set local IP address (by default try to get it)",
        dest="localip",
        default="",
    )
    other.add_argument(
        "-n",
        metavar="REQUESTS",
        type=int,
        help="Number of requests (default: non stop)",
        dest="number",
        default=0,
    )
    other.add_argument(
        "-in",
        metavar="INTERVAL",
        type=int,
        help="Wait interval seconds between sending each packet (default: 1 sec)",
        dest="interval",
        default=1,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ##################
    # invite command #
    ##################
    parser_invite = subparsers.add_parser(
        "invite",
        formatter_class=argparse.RawTextHelpFormatter,
        help="SIP INVITE attack",
        add_help=False,
        description=RED
        + Logo("sipinvite").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """invite"""
        + YELLOW
        + """ checks if a server allow us to make calls without authentication."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Trying to call to a custom number
"""
        + WHITE
        + """     sippts invite -i 192.168.0.1 -tu XXXXXXXXX
"""
        + YELLOW
        + """  Trandfer call (if the response to the INVITE request is 200 Ok)
"""
        + WHITE
        + """     sippts invite -i 192.168.0.1 -tu XXXXXXXXX -t YYYYYYYYY
""",
    )

    target = parser_invite.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )
    target.add_argument(
        "-l",
        metavar="LOCAL_PORT",
        type=int,
        help="Local port (default: first free)",
        dest="lport",
    )
    target.add_argument(
        "-proxy",
        metavar="IP:PORT",
        type=str,
        help="Use an outbound proxy (ex: 192.168.1.1 or 192.168.1.1:5070)",
        dest="proxy",
        default="",
    )

    headers = parser_invite.add_argument_group("Headers")
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-ft",
        metavar="FROM_TAG",
        type=str,
        help="From Tag",
        dest="from_tag",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-ppi",
        metavar="PPI",
        type=str,
        help="P-Preferred-Identity",
        dest="ppi",
        default="",
    )
    headers.add_argument(
        "-pai",
        metavar="PAI",
        type=str,
        help="P-Asserted-Identity",
        dest="pai",
        default="",
    )
    headers.add_argument(
        "-no-sdp",
        help="Do not send SDP (by default is included)",
        dest="nosdp",
        action="count",
    )
    headers.add_argument("-sdes", help="Send SDES in SDP", dest="sdes", action="count")

    auth = parser_invite.add_argument_group("Auth")
    auth.add_argument(
        "-user",
        metavar="AUTH_USER",
        type=str,
        help="Authentication user",
        dest="user",
        default="",
    )
    auth.add_argument(
        "-pass",
        metavar="AUTH_PASS",
        type=str,
        help="Authentication password",
        dest="pwd",
        default="",
    )

    log = parser_invite.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-nocolor", help="Show result without colors", dest="nocolor", action="count"
    )
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save data into a log file",
        dest="ofile",
        default="",
    )

    other = parser_invite.add_argument_group("Other options")
    other.add_argument(
        "-t",
        metavar="NUMBER",
        type=str,
        help="Phone number to transfer the call",
        dest="transfer_number",
        default="",
    )
    other.add_argument(
        "-th",
        metavar="THREADS",
        type=int,
        help="Number of threads (default: 200)",
        dest="threads",
        default=200,
    )
    other.add_argument(
        "-local-ip",
        metavar="IP",
        type=str,
        help="Set local IP address (by default try to get it)",
        dest="localip",
        default="",
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ################
    # dump command #
    ################
    parser_dump = subparsers.add_parser(
        "dump",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Dump SIP digest authentications from a PCAP file",
        add_help=False,
        description=RED
        + Logo("sipdump").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """dump"""
        + YELLOW
        + """ extracts SIP Digest authentications from a PCAP file."""
        + WHITE,
        epilog="""
Usage examples:
"""
        + YELLOW
        + """  Extract SIP authentications from a PCAP file
"""
        + WHITE
        + """     sippts dump -f capture.pcap -o dump.txt
""",
    )

    options = parser_dump.add_argument_group("Options")
    options.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="PCAP file to analyze",
        dest="file",
        default="",
    )
    options.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save digest to file in SipCrack format",
        dest="ofile",
        default="",
    )
    options.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ##################
    # dcrack command #
    ##################
    parser_dcrack = subparsers.add_parser(
        "dcrack",
        formatter_class=argparse.RawTextHelpFormatter,
        help="SIP digest authentication cracking",
        add_help=False,
        description=RED
        + Logo("sipdigestcrack").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """dcrack"""
        + YELLOW
        + """ is a tool to crack the digest authentications within the SIP protocol."""
        + WHITE,
        epilog="""
Bruteforce charsets
-------------------
alphabet=ascii_letters    # The ascii_lowercase and ascii_uppercase constants
alphabet=ascii_lowercase  # The lowercase letters: abcdefghijklmnopqrstuvwxyz
alphabet=ascii_uppercase  # The uppercase letters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
alphabet=digits           # The string: 0123456789
alphabet=hexdigits        # The string: 0123456789abcdefABCDEF
alphabet=octdigits        # The string: 01234567
alphabet=punctuation      # String of ASCII characters: !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
alphabet=printable        # Combination of digits, ascii_letters, punctuation, and whitespace
alphabet=whitespace       # This includes the characters space, tab, linefeed, return, formfeed, and vertical tab
alphabet=0123456789abcdef # Custom alphabet

Usage examples:
"""
        + YELLOW
        + """  Use wordlist
"""
        + WHITE
        + """     sippts dcrack -f dump.txt -w rockyou.txt
"""
        + YELLOW
        + """  Use bruteforce
"""
        + WHITE
        + """     sippts dcrack -f dump.txt -bf -charset printable
"""
        + YELLOW
        + """  Use bruteforce with custom charset
"""
        + WHITE
        + """     sippts dcrack -f dump.txt -bf -charset abc1234567890
""",
    )

    wlist = parser_dcrack.add_argument_group("Wordlist")
    wlist.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="SipCrack format file with SIP Digest hashes",
        dest="file",
        default="",
    )
    wlist.add_argument(
        "-w",
        metavar="FILE",
        help="Wordlist for bruteforce",
        dest="wordlist",
        default="",
    )

    brute = parser_dcrack.add_argument_group("Bruteforce")
    brute.add_argument(
        "-bf", help="Bruteforce password", dest="bruteforce", action="count"
    )
    brute.add_argument(
        "-charset",
        metavar="CHARSET",
        help="Charset for bruteforce (default: printable)",
        dest="charset",
        default="printable",
    )
    brute.add_argument(
        "-min",
        metavar="NUMBER",
        type=int,
        help="Min length for bruteforce (default: 1)",
        dest="min",
        default=1,
    )
    brute.add_argument(
        "-max",
        metavar="NUMBER",
        type=int,
        help="Max length for bruteforce (default: 8)",
        dest="max",
        default=8,
    )
    
    log = parser_dcrack.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")

    options = parser_dcrack.add_argument_group("Other options")
    options.add_argument(
        "-th",
        metavar="THREADS",
        type=int,
        help="Number of threads (default: 10)",
        dest="threads",
        default=10,
    )
    options.add_argument(
        "-p",
        metavar="PREFIX",
        type=str,
        help="Prefix for passwords",
        dest="prefix",
        default="",
    )
    options.add_argument(
        "-s",
        metavar="SUFIX",
        type=str,
        help="Suffix for passwords",
        dest="suffix",
        default="",
    )
    options.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #################
    # flood command #
    #################
    parser_flood = subparsers.add_parser(
        "flood",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Flood a SIP server",
        add_help=False,
        description=RED
        + Logo("sipflood").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """flood"""
        + YELLOW
        + """ flood a server sending messages with a selected method."""
        + WHITE,
    )

    target = parser_flood.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP|HOST", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-r",
        metavar="REMOTE_PORT",
        type=int,
        help="Remote port (default: 5060)",
        dest="rport",
        default=5060,
    )
    target.add_argument(
        "-p",
        metavar="PROTOCOL",
        type=str.upper,
        help="Protocol: udp|tcp|tls (default: udp)",
        dest="proto",
        choices=["UDP", "TCP", "TLS"],
        default="udp",
    )

    headers = parser_flood.add_argument_group("Headers")
    headers.add_argument(
        "-m",
        metavar="METHOD",
        type=str.upper,
        help="SIP method: options, invite, register (default: options)",
        dest="method",
        choices=["OPTIONS", "REGISTER", "INVITE"],
        default="options",
    )
    headers.add_argument(
        "-d",
        metavar="DOMAIN",
        type=str,
        help="SIP Domain or IP address. Ex: my.sipserver.com (default: target IP address)",
        dest="domain",
        default="",
    )
    headers.add_argument(
        "-cd",
        metavar="CONTACT_DOMAIN",
        type=str,
        help="Domain or IP address for Contact header. Ex: 10.0.1.2",
        dest="contact_domain",
        default="",
    )
    headers.add_argument(
        "-fn",
        metavar="FROM_NAME",
        type=str,
        help="From Name. Ex: Bob",
        dest="from_name",
        default="",
    )
    headers.add_argument(
        "-fu",
        metavar="FROM_USER",
        type=str,
        help="From User (default: 100)",
        dest="from_user",
        default="100",
    )
    headers.add_argument(
        "-fd",
        metavar="FROM_DOMAIN",
        type=str,
        help="From Domain. Ex: 10.0.0.1",
        dest="from_domain",
        default="",
    )
    headers.add_argument(
        "-tn",
        metavar="TO_NAME",
        type=str,
        help="To Name. Ex: Alice",
        dest="to_name",
        default="",
    )
    headers.add_argument(
        "-tu",
        metavar="TO_USER",
        type=str,
        help="To User (default: 100)",
        dest="to_user",
        default="100",
    )
    headers.add_argument(
        "-td",
        metavar="TO_DOMAIN",
        type=str,
        help="To Domain. Ex: 10.0.0.1",
        dest="to_domain",
        default="",
    )
    headers.add_argument(
        "-ua",
        metavar="USER_AGENT",
        type=str,
        help="User-Agent header (default: pplsip)",
        dest="user_agent",
        default="pplsip",
    )
    headers.add_argument(
        "-digest",
        metavar="DIGEST",
        type=str,
        help="Add a customized Digest header",
        dest="digest",
        default="",
    )

    log = parser_flood.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save data into a log file",
        dest="ofile",
        default="",
    )

    fuzz = parser_flood.add_argument_group("Fuzzing")
    fuzz.add_argument("-b", help="Send malformed headers", dest="bad", action="count")
    fuzz.add_argument(
        "-charset",
        metavar="CHARSET",
        help='Alphabet [all|printable|ascii|hex] (by default: printable characters) -  "-b required"',
        dest="alphabet",
        default="printable",
    )
    fuzz.add_argument(
        "-min",
        metavar="NUMBER",
        type=int,
        help='Min length (default: 0) -  "-b required"',
        dest="min",
        default=0,
    )
    fuzz.add_argument(
        "-max",
        metavar="NUMBER",
        type=int,
        help='Max length (default: 1000) - "-b required"',
        dest="max",
        default=1000,
    )

    other = parser_flood.add_argument_group("Other options")
    other.add_argument(
        "-th",
        metavar="THREADS",
        type=int,
        help="Number of threads (default: 200)",
        dest="threads",
        default=200,
    )
    other.add_argument(
        "-n",
        "--number",
        type=int,
        help="Number of requests (by default: non stop)",
        dest="number",
        default=0,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #################
    # sniff command #
    #################
    parser_sniff = subparsers.add_parser(
        "sniff",
        formatter_class=argparse.RawTextHelpFormatter,
        help="SIP network sniffing",
        add_help=False,
        description=RED
        + Logo("sipsniff").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """sniff"""
        + YELLOW
        + """ is a network sniffer for SIP protocol."""
        + WHITE,
    )

    options = parser_sniff.add_argument_group("Options")
    options.add_argument(
        "-d",
        metavar="DEV",
        help="Set Device (by default try to get it)",
        dest="dev",
        default="",
    )
    options.add_argument(
        "-p",
        metavar="PROTOCOL",
        help="Protocol to sniff: udp|tcp|tls|all",
        dest="proto",
        default="all",
    )

    log = parser_sniff.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-o",
        metavar="FILE",
        type=str,
        help="Save data into a log file",
        dest="ofile",
        default="",
    )

    other = parser_sniff.add_argument_group("Other options")
    other.add_argument(
        "-auth", help="Show only auth digest", dest="auth", action="count"
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #################
    # spoof command #
    #################
    parser_spoof = subparsers.add_parser(
        "spoof",
        formatter_class=argparse.RawTextHelpFormatter,
        help="ARP Spoofing tool",
        add_help=False,
        description=RED
        + Logo("arpspoof").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """spoof"""
        + YELLOW
        + """ initiates ARP spoofing attack."""
        + WHITE,
    )

    target = parser_spoof.add_argument_group("Target")
    target.add_argument(
        "-i",
        metavar="IP",
        type=str,
        help="Target IP address (ex: 192.168.0.10 | 192.168.0.0/24 | 192.168.0.1,192.168.0.2)",
        dest="ipaddr",
    )
    target.add_argument(
        "-gw",
        metavar="IP",
        help="Set Gateway (by default try to get it)",
        dest="gw",
        default="",
    )
    target.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="File with several IPs or network ranges",
        dest="file",
        default="",
    )

    log = parser_spoof.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-vv", help="Increase more verbosity", dest="more_verbose", action="count"
    )

    other = parser_spoof.add_argument_group("Other options")
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ####################
    # pcapdump command #
    ####################
    parser_pcapdump = subparsers.add_parser(
        "pcapdump",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Extract data from a PCAP file",
        add_help=False,
        description=RED
        + Logo("sippcapdump").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """pcapdump"""
        + YELLOW
        + """ extracts data from a PCAP file."""
        + WHITE,
    )

    target = parser_pcapdump.add_argument_group("Target")
    target.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="PCAP file to analyze",
        dest="file",
        default="",
    )
    target.add_argument("-sip", help="Show SIP frames", dest="sip", action="count")
    target.add_argument("-rtp", help="Show RTP frames", dest="rtp", action="count")
    target.add_argument(
        "-auth", help="Show SIP authentications", dest="auth", action="count"
    )

    rtp = parser_pcapdump.add_argument_group("RTP")
    rtp.add_argument(
        "-r",
        "-rtp_extract",
        help="Extract RTP streams into WAV files",
        dest="rtp_extract",
        action="count",
    )

    log = parser_pcapdump.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")
    log.add_argument(
        "-o",
        metavar="FOLDER",
        type=str,
        help="Save data into a folder",
        dest="folder",
        default="",
    )

    other = parser_pcapdump.add_argument_group("Other options")
    other.add_argument(
        "-nocolor", help="Show result without colors", dest="nocolor", action="count"
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ####################
    # rtpbleed command #
    ####################
    parser_rtpbleed = subparsers.add_parser(
        "rtpbleed",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Detect RTPBleed vulnerability (send RTP streams)",
        add_help=False,
        description=RED
        + Logo("rtpbleed").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """rtpbleed"""
        + YELLOW
        + """ detects the RTP Bleed vulnerability sending RTP streams. More info about the vulnerability: https://www.rtpbleed.com/"""
        + WHITE
        + """

Payloads
--------
   0 PCMU  (audio)
   3 GSM   (audio)
   4 G723  (audio)
   5 DVI4  (audio)
   6 DVI4  (audio)
   7 LPC   (audio)
   8 PCMA  (audio)
   9 G722  (audio)
  10 L16   (audio)
  11 L16   (audio)
  12 QCELP (audio)
  13 CN    (audio)
  14 MPA   (audio)
  15 G728  (audio)
  16 DVI4  (audio)
  17 DVI4  (audio)
  18 G729  (audio)
  25 CELLB (video)
  26 JPEG  (video)
  28 nv    (video)
  31 H261  (video)
  32 MPV   (video)
  33 MP2T  (audio/video)
  34 H263  (video)
""",
    )

    target = parser_rtpbleed.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP", type=str, help="Target IP address", dest="ipaddr"
    )

    other = parser_rtpbleed.add_argument_group("Other options")
    other.add_argument(
        "-s",
        metavar="PORT",
        type=int,
        help="Start port of the host (default: 10000)",
        dest="start_port",
        default=10000,
    )
    other.add_argument(
        "-e",
        metavar="PORT",
        type=int,
        help="End port of the host (default: 20000)",
        dest="end_port",
        default=20000,
    )
    other.add_argument(
        "-l",
        metavar="LOOPS",
        type=int,
        help="Number of times to probe the port ranges on the target(s) (default: 4)",
        dest="loops",
        default=4,
    )
    other.add_argument(
        "-p",
        metavar="PAYLOAD",
        type=int,
        help="Codec payload (default: 0)",
        dest="payload",
        default=0,
    )
    other.add_argument(
        "-d",
        metavar="DELAY",
        dest="delay",
        type=int,
        help="Delay for timeout in microseconds (default: 1)",
        default=1,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #####################
    # rtcpbleed command #
    #####################
    parser_rtcpbleed = subparsers.add_parser(
        "rtcpbleed",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Detect RTPBleed vulnerability (send RTCP streams)",
        add_help=False,
        description=RED
        + Logo("rtcpbleed").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """rtcpbleed"""
        + YELLOW
        + """ detects the RTP Bleed vulnerability sending RTCP streams. More info about the vulnerability: https://www.rtpbleed.com/"""
        + WHITE,
    )

    target = parser_rtcpbleed.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP", type=str, help="Target IP address", dest="ipaddr"
    )

    other = parser_rtcpbleed.add_argument_group("Other options")
    other.add_argument(
        "-s",
        metavar="PORT",
        type=int,
        help="Start port of the host (default: 10001)",
        dest="start_port",
        default=10001,
    )
    other.add_argument(
        "-e",
        metavar="PORT",
        type=int,
        help="End port of the host (default: 20001)",
        dest="end_port",
        default=20001,
    )
    other.add_argument(
        "-d",
        metavar="DELAY",
        dest="delay",
        type=int,
        help="Delay for timeout in microseconds (default: 1)",
        default=1,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    #########################
    # rtpbleedflood command #
    #########################
    parser_rtpbleedflood = subparsers.add_parser(
        "rtpbleedflood",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Exploit RTPBleed vulnerability (flood RTP)",
        add_help=False,
        description=RED
        + Logo("rtpbleedflood").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """rtpbleedflood"""
        + YELLOW
        + """ exploit the RTP Bleed vulnerability sending RTP streams. More info about the vulnerability: https://www.rtpbleed.com/"""
        + WHITE,
    )

    target = parser_rtpbleedflood.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP", type=str, help="Target IP address", dest="ipaddr"
    )

    log = parser_rtpbleedflood.add_argument_group("Log")
    log.add_argument("-v", help="Increase verbosity", dest="verbose", action="count")

    other = parser_rtpbleedflood.add_argument_group("Other options")
    other.add_argument(
        "-r", metavar="PORT", type=int, help="Port number to flood", dest="rport"
    )
    other.add_argument(
        "-p",
        metavar="PAYLOAD",
        type=int,
        help="Codec payload (default: 0)",
        dest="payload",
        default=0,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ##########################
    # rtpbleedinject command #
    ##########################
    parser_rtpbleedinject = subparsers.add_parser(
        "rtpbleedinject",
        formatter_class=argparse.RawTextHelpFormatter,
        help="Exploit RTPBleed vulnerability (inject WAV file)",
        add_help=False,
        description=RED
        + Logo("rtpbleedinject").get_logo()
        + YELLOW
        + """
  Module """
        + BYELLOW
        + """rtpbleedinject"""
        + YELLOW
        + """ exploit the RTP Bleed vulnerability injecting RTP streams. More info about the vulnerability: https://www.rtpbleed.com/"""
        + WHITE,
    )

    target = parser_rtpbleedinject.add_argument_group("Target")
    target.add_argument(
        "-i", metavar="IP", type=str, help="Target IP address", dest="ipaddr"
    )
    target.add_argument(
        "-f",
        metavar="FILE",
        type=str,
        help="Audio file (WAV) to inject",
        dest="file",
        default="",
    )

    other = parser_rtpbleedinject.add_argument_group("Other options")
    other.add_argument(
        "-r", metavar="PORT", type=int, help="Port number to flood", dest="rport"
    )
    other.add_argument(
        "-p",
        metavar="PAYLOAD",
        type=int,
        help="Codec payload (default: 0)",
        dest="payload",
        default=0,
    )
    other.add_argument(
        "-h", "--help", help="Show this help", dest="help", action="count"
    )

    ################
    # Parse params #
    ################
    args = parser.parse_args()

    # Update scripts
    if args.update == 1:
        import sysconfig

        path = sysconfig.get_paths()["purelib"] + "/sippts/data/cve.csv"
        if not os.path.isfile(path):
            path = path.replace("/usr/", "/usr/local/").replace(
                "site-packages", "dist-packages"
            )

        modulepath = sysconfig.get_paths()["purelib"] + "/sippts/"
        if not os.path.isdir(modulepath):
            modulepath = modulepath.replace("/usr/", "/usr/local/").replace(
                "site-packages", "dist-packages"
            )

        binpath = sysconfig.get_paths()["scripts"] + "/sippts"
        if not os.path.isfile(binpath):
            binpath = binpath.replace("/usr/", "/usr/local/").replace(
                "site-packages", "dist-packages"
            )

        giturl = "https://raw.githubusercontent.com/Pepelux/sippts/master/"

        try:
            command = [
                "curl",
                "https://raw.githubusercontent.com/Pepelux/sippts/master/version",
                "-H 'Cache-Control: no-cache, no-store'",
            ]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            output = result.stdout
            error = result.stderr

            if result.returncode == 0 and output != "404: Not Found":
                current_cve_version = output.replace("\n", "")
            else:
                print(f"{BRED}Error downloading scripts")
                print(WHITE)
                sys.exit()
        except:
            sys.exit()

        if local_version != current_version:
            download_file(giturl + "bin/sippts", binpath, "bin/sippts")

            download_file(
                giturl + "src/sippts/lib/color.py",
                modulepath + "lib/color.py",
                "lib/color.py",
            )
            download_file(
                giturl + "src/sippts/lib/functions.py",
                modulepath + "lib/functions.py",
                "lib/functions.py",
            )
            download_file(
                giturl + "src/sippts/lib/logos.py",
                modulepath + "lib/logos.py",
                "lib/logos.py",
            )
            download_file(
                giturl + "src/sippts/lib/params.py",
                modulepath + "lib/params.py",
                "lib/params.py",
            )
            download_file(
                giturl + "src/sippts/lib/videos.py",
                modulepath + "lib/videos.py",
                "lib/videos.py",
            )

            download_file(
                giturl + "src/sippts/arpspoof.py",
                modulepath + "arpspoof.py",
                "arpspoof.py",
            )
            download_file(
                giturl + "src/sippts/rtcpbleed.py",
                modulepath + "rtcpbleed.py",
                "rtcpbleed.py",
            )
            download_file(
                giturl + "src/sippts/rtpbleed.py",
                modulepath + "rtpbleed.py",
                "rtpbleed.py",
            )
            download_file(
                giturl + "src/sippts/rtpbleedflood.py",
                modulepath + "rtpbleedflood.py",
                "rtpbleedflood.py",
            )
            download_file(
                giturl + "src/sippts/rtpbleedinject.py",
                modulepath + "rtpbleedinject.py",
                "rtpbleedinject.py",
            )
            download_file(
                giturl + "src/sippts/sipdigestcrack.py",
                modulepath + "sipdigestcrack.py",
                "sipdigestcrack.py",
            )
            download_file(
                giturl + "src/sippts/sipdigestleak.py",
                modulepath + "sipdigestleak.py",
                "sipdigestleak.py",
            )
            download_file(
                giturl + "src/sippts/sipenumerate.py",
                modulepath + "sipenumerate.py",
                "sipenumerate.py",
            )
            download_file(
                giturl + "src/sippts/sipexten.py",
                modulepath + "sipexten.py",
                "sipexten.py",
            )
            download_file(
                giturl + "src/sippts/sipflood.py",
                modulepath + "sipflood.py",
                "sipflood.py",
            )
            download_file(
                giturl + "src/sippts/sipinvite.py",
                modulepath + "sipinvite.py",
                "sipinvite.py",
            )
            download_file(
                giturl + "src/sippts/sipdump.py",
                modulepath + "sipdump.py",
                "sipdump.py",
            )
            download_file(
                giturl + "src/sippts/sippcapdump.py",
                modulepath + "sippcapdump.py",
                "sippcapdump.py",
            )
            download_file(
                giturl + "src/sippts/sipping.py",
                modulepath + "sipping.py",
                "sipping.py",
            )
            download_file(
                giturl + "src/sippts/siprcrack.py",
                modulepath + "siprcrack.py",
                "siprcrack.py",
            )
            download_file(
                giturl + "src/sippts/sipscan.py",
                modulepath + "sipscan.py",
                "sipscan.py",
            )
            download_file(
                giturl + "src/sippts/sipsend.py",
                modulepath + "sipsend.py",
                "sipsend.py",
            )
            download_file(
                giturl + "src/sippts/sipsniff.py",
                modulepath + "sipsniff.py",
                "sipsniff.py",
            )
            download_file(
                giturl + "src/sippts/wssend.py", modulepath + "wssend.py", "wssend.py"
            )

            print(f"{BYELLOW}SIPPTS has been updated")
        else:
            print(f"{BYELLOW}SIPPTS is in the last version")

        # CVE file
        local_cve_version = load_cve_version()

        try:
            command = [
                "curl",
                giturl + "cveversion",
                "-H 'Cache-Control: no-cache, no-store'",
            ]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            output = result.stdout
            error = result.stderr

            if result.returncode == 0 and output != "404: Not Found":
                current_cve_version = output.replace("\n", "")
            else:
                print(f"{BRED}Error downloading CVE file")
                print(WHITE)
                sys.exit()
        except:
            sys.exit()

        if local_cve_version != current_cve_version:
            download_file(giturl + "src/sippts/data/cve.csv", path)
            print(f"{BYELLOW}CVE file has been updated")
        else:
            print(f"{BYELLOW}CVE file is in the last version")

        print(WHITE)

        sys.exit()

    COMMAND = args.command

    if COMMAND == "video":
        if args.help == 1:
            parser_video.print_help()
            exit()
        if not args.basic and not args.digest and not args.leak and not args.spoof:
            parser_video.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-b{WHITE} or {GREEN}-d{WHITE} or {GREEN}-l{WHITE} or {GREEN}-s"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        BASIC = args.basic
        DIGEST = args.digest
        LEAK = args.leak
        SPOOF = args.spoof

        return COMMAND, BASIC, DIGEST, LEAK, SPOOF
    elif COMMAND == "scan":
        if args.help == 1:
            parser_scan.print_help()
            exit()
        if not args.ipaddr and not args.file:
            parser_scan.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>{WHITE} or {GREEN}-f <FILE>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        PORT = args.rport
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
        TIMEOUT = args.timeout
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        PING = args.ping
        FILE = args.file
        NOCOLOR = args.nocolor
        OFILE = args.ofile
        OIFILE = args.oifile
        FP = args.fp
        RANDOM = args.random
        PPI = args.ppi
        PAI = args.pai
        LOCALIP = args.localip
        CVE = args.cve

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            PORT,
            PROTO,
            METHOD,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            TONAME,
            TOUSER,
            TODOMAIN,
            UA,
            THREADS,
            TIMEOUT,
            VERBOSE,
            PING,
            FILE,
            NOCOLOR,
            OFILE,
            OIFILE,
            FP,
            RANDOM,
            PPI,
            PAI,
            LOCALIP,
            CVE,
        )
    elif COMMAND == "exten":
        if args.help == 1:
            parser_exten.print_help()
            exit()
        if not args.ipaddr:
            parser_exten.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.rport
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
        TIMEOUT = args.timeout

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            RPORT,
            EXTEN,
            PREFIX,
            PROTO,
            METHOD,
            DOMAIN,
            CONTACTDOMAIN,
            FROMUSER,
            UA,
            THREADS,
            VERBOSE,
            NOCOLOR,
            OFILE,
            FILTER,
            TIMEOUT,
        )
    elif COMMAND == "rcrack":
        if args.help == 1:
            parser_rcrack.print_help()
            exit()
        if not args.ipaddr or not args.exten or not args.wordlist:
            parser_rcrack.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>{WHITE} and {GREEN}-e <EXTEN>{WHITE} and {GREEN}-w <WORDLIST>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PROXY = args.proxy
        RPORT = args.rport
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
        TIMEOUT = args.timeout

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            RPORT,
            EXTEN,
            PREFIX,
            AUTHUSER,
            LENGHT,
            PROTO,
            DOMAIN,
            CONTACTDOMAIN,
            UA,
            WORDLIST,
            THREADS,
            VERBOSE,
            NOCOLOR,
            TIMEOUT,
        )
    elif COMMAND == "send":
        if args.help == 1:
            parser_send.print_help()
            exit()
        if not args.ipaddr:
            parser_send.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        HOST = args.ipaddr
        TEMPLATE = args.template
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
        HEADER = args.header
        NOCONTACT = args.nocontact
        TIMEOUT = args.timeout
        VERBOSE = args.verbose

        return (
            COMMAND,
            IPADDR,
            HOST,
            TEMPLATE,
            PROXY,
            RPORT,
            LPORT,
            PROTO,
            METHOD,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            FROMTAG,
            TONAME,
            TOUSER,
            TODOMAIN,
            TOTAG,
            USER,
            PWD,
            DIGEST,
            BRANCH,
            CALLID,
            CSEQ,
            SDP,
            SDES,
            UA,
            LOCALIP,
            NOCOLOR,
            OFILE,
            PPI,
            PAI,
            HEADER,
            NOCONTACT,
            TIMEOUT,
            VERBOSE,
        )
    elif COMMAND == "wssend":
        if args.help == 1:
            parser_wssend.print_help()
            exit()
        if not args.ipaddr:
            parser_wssend.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        PORT = args.rport
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
        LOCALIP = args.localip

        return (
            COMMAND,
            IPADDR,
            PORT,
            PATH,
            VERBOSE,
            PROTO,
            METHOD,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            FROMTAG,
            TONAME,
            TOUSER,
            TOTAG,
            TODOMAIN,
            UA,
            LOCALIP,
            PPI,
            PAI,
        )
    elif COMMAND == "enumerate":
        if args.help == 1:
            parser_enumerate.print_help()
            exit()
        if not args.ipaddr:
            parser_enumerate.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

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
        TIMEOUT = args.timeout

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            RPORT,
            PROTO,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            TONAME,
            TOUSER,
            TODOMAIN,
            UA,
            VERBOSE,
            TIMEOUT,
        )
    elif COMMAND == "leak":
        if args.help == 1:
            parser_leak.print_help()
            exit()
        if not args.ipaddr and not args.file:
            parser_leak.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>{WHITE} or {GREEN}-f <FILE>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

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

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            RPORT,
            PROTO,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            TONAME,
            TOUSER,
            TODOMAIN,
            UA,
            LOCALIP,
            OFILE,
            LFILE,
            USER,
            PWD,
            AUTH,
            VERBOSE,
            SDP,
            SDES,
            FILE,
            PING,
            PPI,
            PAI,
        )
    elif COMMAND == "ping":
        if args.help == 1:
            parser_ping.print_help()
            exit()
        if not args.ipaddr:
            parser_ping.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

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
        TIMEOUT = args.timeout

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            RPORT,
            PROTO,
            METHOD,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            FROMTAG,
            TONAME,
            TOUSER,
            TODOMAIN,
            TOTAG,
            USER,
            PWD,
            DIGEST,
            BRANCH,
            CALLID,
            CSEQ,
            UA,
            LOCALIP,
            NUMBER,
            INTERVAL,
            PPI,
            PAI,
            TIMEOUT,
        )
    elif COMMAND == "invite":
        if args.help == 1:
            parser_invite.print_help()
            exit()
        if not args.ipaddr:
            parser_invite.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

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

        return (
            COMMAND,
            IPADDR,
            HOST,
            PROXY,
            RPORT,
            LPORT,
            PROTO,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            TONAME,
            TOUSER,
            TODOMAIN,
            TRANSFER,
            USER,
            PWD,
            UA,
            LOCALIP,
            THREADS,
            NOSDP,
            VERBOSE,
            SDES,
            NOCOLOR,
            OFILE,
            PPI,
            PAI,
        )
    elif COMMAND == "dump":
        if args.help == 1:
            parser_dump.print_help()
            exit()
        if not args.file or not args.ofile:
            parser_dump.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-f <FILE>{WHITE} and {GREEN}-o <FILE>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        FILE = args.file
        OFILE = args.ofile

        return COMMAND, FILE, OFILE
    elif COMMAND == "dcrack":
        if args.help == 1:
            parser_dcrack.print_help()
            exit()
        if not args.file:
            parser_dcrack.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-f <FILE>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()
        if (not args.bruteforce and not args.wordlist) or (args.bruteforce and args.wordlist):
            parser_dcrack.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-bf{WHITE} or {GREEN}-w <FILE>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        FILE = args.file
        WORDLIST = args.wordlist
        BRUTEFORCE = args.bruteforce
        MAX = args.max
        MIN = args.min
        CHARSET = args.charset
        PREFIX = args.prefix
        SUFFIX = args.suffix
        VERBOSE = args.verbose
        THREADS = args.threads

        return (
            COMMAND,
            FILE,
            VERBOSE,
            WORDLIST,
            BRUTEFORCE,
            CHARSET,
            MAX,
            MIN,
            PREFIX,
            SUFFIX,
            THREADS
        )
    elif COMMAND == "flood":
        if args.help == 1:
            parser_flood.print_help()
            exit()
        if not args.ipaddr:
            parser_flood.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()
        if (args.alphabet == 1 or args.min == 1 or args.max == 1) and args.bad == 0:
            parser_flood.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-b{WHITE} when select {GREEN}-charset / -min / -max"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

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
        NUMBER = args.number
        BAD = args.bad
        ALPHABET = args.alphabet
        MIN = args.min
        MAX = args.max

        return (
            COMMAND,
            IPADDR,
            HOST,
            RPORT,
            PROTO,
            METHOD,
            DOMAIN,
            CONTACTDOMAIN,
            FROMNAME,
            FROMUSER,
            FROMDOMAIN,
            TONAME,
            TOUSER,
            TODOMAIN,
            DIGEST,
            UA,
            THREADS,
            VERBOSE,
            NUMBER,
            BAD,
            ALPHABET,
            MAX,
            MIN,
        )
    elif COMMAND == "sniff":
        if args.help == 1:
            parser_sniff.print_help()
            exit()

        DEV = args.dev
        OFILE = args.ofile
        PROTO = args.proto
        AUTH = args.auth
        VERBOSE = args.verbose

        return COMMAND, DEV, OFILE, AUTH, VERBOSE, PROTO
    elif COMMAND == "spoof":
        if args.help == 1:
            parser_spoof.print_help()
            exit()
        if not args.ipaddr and not args.file:
            parser_spoof.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP|HOST>{WHITE} or {GREEN}-f <FILE>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        GW = args.gw
        FILE = args.file
        VERBOSE = args.verbose

        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2

        return COMMAND, IPADDR, VERBOSE, GW, FILE
    elif COMMAND == "pcapdump":
        if args.help == 1:
            parser_pcapdump.print_help()
            exit()
        if not args.file:
            parser_pcapdump.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-f <FILE>" + WHITE
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()
        if not args.sip and not args.rtp and not args.auth and not args.rtp_extract:
            parser_pcapdump.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-sip{WHITE} or {GREEN}-rtp{WHITE} or {GREEN}-auth{WHITE} or {GREEN}-r"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        FILE = args.file
        SIP = args.sip
        AUTH = args.auth
        RTP = args.rtp
        VERBOSE = args.verbose
        FOLDER = args.folder
        RTPEXTRACT = args.rtp_extract
        NOCOLOR = args.nocolor

        return COMMAND, FILE, FOLDER, VERBOSE, RTPEXTRACT, NOCOLOR, SIP, RTP, AUTH
    elif COMMAND == "rtpbleed":
        if args.help == 1:
            parser_rtpbleed.print_help()
            exit()
        if not args.ipaddr:
            parser_rtpbleed.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

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
        return COMMAND, IPADDR, SP, EP, LOOPS, PAYLOAD, DELAY
    elif COMMAND == "rtcpbleed":
        if args.help == 1:
            parser_rtcpbleed.print_help()
            exit()
        if not args.ipaddr:
            parser_rtcpbleed.print_help()
            print(RED)
            print("Param error!")
            print(f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP>")
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        SP = args.start_port
        EP = args.end_port
        # Always start on odd port
        if SP % 2 == 0:
            SP = SP + 1
        if EP % 2 == 0:
            EP = EP + 1
        DELAY = args.delay
        return COMMAND, IPADDR, SP, EP, DELAY
    elif COMMAND == "rtpbleedflood":
        if args.help == 1:
            parser_rtpbleedflood.print_help()
            exit()
        if not args.ipaddr or not args.rport:
            parser_rtpbleedflood.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP>{WHITE} and {GREEN}-r <PORT>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        P = args.rport
        PAYLOAD = args.payload
        VERBOSE = args.verbose

        return COMMAND, IPADDR, P, PAYLOAD, VERBOSE
    elif COMMAND == "rtpbleedinject":
        if args.help == 1:
            parser_rtpbleedinject.print_help()
            exit()
        if not args.ipaddr or not args.rport or not args.file:
            parser_rtpbleedinject.print_help()
            print(RED)
            print("Param error!")
            print(
                f"{BWHITE}{COMMAND}:{WHITE} Mandatory params: {GREEN}-i <IP>{WHITE} and {GREEN}-r <PORT>{WHITE} and {GREEN}-f <FILE>"
            )
            print(f"{WHITE}Use {CYAN}sippts {COMMAND} -h/--help{WHITE} for help")
            exit()

        IPADDR = args.ipaddr
        P = args.rport
        PAYLOAD = args.payload
        FILE = args.file

        return COMMAND, IPADDR, P, PAYLOAD, FILE
    else:
        parser.print_help()
        exit()


def download_file(url, path, file):
    command = ["curl", url, "-H 'Cache-Control: no-cache, no-store'"]
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    output = result.stdout
    error = result.stderr

    if result.returncode != 0 or output == "404: Not Found":
        print(f"{BRED}Error downloading file {BGREEN}{url}")

    else:
        print(f"{WHITE}Updating {file}")

        r = requests.get(url)
        open(path, "wb").write(r.content)
